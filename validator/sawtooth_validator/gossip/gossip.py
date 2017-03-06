# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------
import logging
import copy
from threading import Condition
from functools import partial

from sawtooth_validator.protobuf import validator_pb2
from sawtooth_validator.protobuf.network_pb2 import GossipMessage
from sawtooth_validator.protobuf.network_pb2 import GossipBatchByBatchIdRequest
from sawtooth_validator.protobuf.network_pb2 import \
    GossipBatchByTransactionIdRequest
from sawtooth_validator.protobuf.network_pb2 import GossipBlockRequest
from sawtooth_validator.protobuf.network_pb2 import PeerRegisterRequest
from sawtooth_validator.protobuf.network_pb2 import HelloMessage
from sawtooth_validator.protobuf.network_pb2 import NetworkAcknowledgement

LOGGER = logging.getLogger(__name__)


def get_message_type_name(enum_value):
    return validator_pb2.Message.MessageType.Name(enum_value)


class Gossip(object):
    def __init__(self, network, initial_connections=None,
                 max_connections=100):
        self._condition = Condition()
        self._network = network
        self._identities = []
        self._initial_connections = initial_connections \
                if initial_connections else []
        self.max_connections = max_connections
        self.num_connections = 0

    def register_identity(self, identity):
        """Registers a connected identity.

        Args:
            identity (str): A unique identifier which identifies an
                incoming connection on the network server socket.
        """
        with self._condition:
            self._identities.append(identity)
        LOGGER.debug("Added identity %s, connected identities are now %s",
                     identity, self._identities)

    def unregister_identity(self, identity):
        """Removes an identity from the registry.

        Args:
            identity (str): A unique identifier which identifies an
                incoming connection on the network server socket.
        """
        with self._condition:
            if identity in self._identities:
                self._identities.remove(identity)
                LOGGER.debug("Removed identity %s, "
                             "connected identities are now %s",
                             identity, self._identities)
            else:
                LOGGER.debug("Attempt to unregister identity %s failed: "
                             "identity was not registered")

    def broadcast_block(self, block, exclude=None):
        gossip_message = GossipMessage(
            content_type="BLOCK",
            content=block.SerializeToString())

        self.broadcast(
            gossip_message, validator_pb2.Message.GOSSIP_MESSAGE, exclude)

    def broadcast_block_request(self, block_id):
        # Need to define node identity to be able to route directly back
        block_request = GossipBlockRequest(block_id=block_id)
        self.broadcast(block_request,
                       validator_pb2.Message.GOSSIP_BLOCK_REQUEST)

    def broadcast_batch(self, batch, exclude=None):
        gossip_message = GossipMessage(
            content_type="BATCH",
            content=batch.SerializeToString())

        self.broadcast(
            gossip_message, validator_pb2.Message.GOSSIP_MESSAGE, exclude)

    def broadcast_batch_by_transaction_id_request(self, transaction_ids):
        # Need to define node identity to be able to route directly back
        batch_request = GossipBatchByTransactionIdRequest(
            ids=transaction_ids
        )
        self.broadcast(
            batch_request,
            validator_pb2.Message.GOSSIP_BATCH_BY_TRANSACTION_ID_REQUEST)

    def broadcast_batch_by_batch_id_request(self, batch_id):
        # Need to define node identity to be able to route directly back
        batch_request = GossipBatchByBatchIdRequest(
            id=batch_id
        )
        self.broadcast(
            batch_request,
            validator_pb2.Message.GOSSIP_BATCH_BY_BATCH_ID_REQUEST)

    def send(self, identity, connection, gossip_message, message_type):
        LOGGER.debug("Trying direct send to identity %s connection %s",
                     identity,
                     connection)

        if connection == "ServerThread":
            self._network.send(message_type,
                               gossip_message.SerializeToString(),
                               identity)
        else:
            self._network.outbound_connections[connection].send(message_type,
                            gossip_message.SerializeToString())

    def broadcast(self, gossip_message, message_type, exclude=None):
        """Broadcast gossip messages.

        Broadcast to both connected identities on our server socket and to
        outboud connections we have originated. If a peer's identifiers are in
        exclude, do not broadcast message to them.

        Args:
            gossip_message: The message to be broadcast.
            message_type: Type of the message.
            exclude: A list of tuples that contains a peer's information
                (connection, identifier)
        """
        if exclude is None:
            exclude = []

        excluded_inbound_peers = [peer[1] for peer in exclude]
        excluded_outbound_peers = [peer[0].split('-')[1] for peer in exclude if peer[0] != "ServerThread"]
        LOGGER.critical("Excluding outbound %s", excluded_outbound_peers)

        for identity in self._identities:
            if identity not in excluded_inbound_peers:
                self._network.send(message_type,
                                   gossip_message.SerializeToString(),
                                   identity)

        LOGGER.critical("Outbound Connections: %s", self._network.outbound_connections.items())
        for conn_id, connection in self._network.outbound_connections.items():
            if conn_id not in excluded_outbound_peers:
                connection.send(message_type,
                                gossip_message.SerializeToString())

    def _hello_callback(self, request, result, network=None, connection=None):
        ack = NetworkAcknowledgement()
        ack.ParseFromString(result.content)

        if ack.status == ack.ERROR:
            LOGGER.debug("Got an error response to our hello")
            if network:
                if connection:
                    # Maybe a status update instead?
                    network.remove_connection(connection)
                else:
                    LOGGER.debug("Unknown connection")
            else:
                LOGGER.debug("Unknown network")
        elif ack.status == ack.OK:
            LOGGER.debug("Hello ack'd. Connecting")
            register_request = PeerRegisterRequest()
            connection.send(validator_pb2.Message.GOSSIP_REGISTER,
                            register_request.SerializeToString(),
                            callback=partial(self._register_callback,
                                             network=self._network,
                                             connection=connection))

    def _register_callback(self, request, result,
                           network=None, connection=None):
        ack = NetworkAcknowledgement()
        ack.ParseFromString(result.content)

        if ack.status == ack.ERROR:
            LOGGER.debug("Got an error response to our register")
        elif ack.status == ack.OK:
            LOGGER.debug("Registration ack'd. Peered")
            LOGGER.debug("Requesting current head block")
            self.broadcast_block_request("HEAD")

    def start(self):
        try:
            LOGGER.debug("Starting gossip with %s initial connections",
                         len(self._initial_connections))
            hello_message = HelloMessage()

            for uri in self._initial_connections:
                connection = self._network.add_connection(uri)
                connection.send(validator_pb2.Message.GOSSIP_HELLO,
                                hello_message.SerializeToString(),
                                callback=partial(self._hello_callback,
                                                 network=self._network,
                                                 connection=connection))
        except Exception as e:
            LOGGER.exception(e)
