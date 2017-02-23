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

from sawtooth_validator.networking.dispatch import Handler
from sawtooth_validator.networking.dispatch import HandlerResult
from sawtooth_validator.networking.dispatch import HandlerStatus
from sawtooth_validator.protobuf import network_pb2
from sawtooth_validator.protobuf import validator_pb2

LOGGER = logging.getLogger(__name__)


class Responder(object):
    def __init__(self, completer):
        self.completer = completer

    def check_for_block(self, block_id):
        # Ask Completer
        block = self.completer.get_block(block_id)
        return block

    def check_for_batch(self, batch_id):
        batch = self.completer.get_batch(batch_id)
        return batch

    def check_for_batch_by_transaction(self, transaction_id):
        batch = self.completer.get_batch(transaction_id)
        return batch


class BlockResponderHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip

    def handle(self, identity, message_content):
        gossip_message = network_pb2.GossipBlockRequest()
        gossip_message.ParseFromString(message_content)
        block_id = gossip_message.block_id
        block = self._responder.check_for_block(block_id)
        if block is None:
            # No block found, broadcast orignal message to other peers
            self._gossip.broadcast(gossip_message,
                                   validator_pb2.Message.GOSSIP_BLOCK_REQUEST)
        else:
            # Found block, Currently we create a new gossip message, in the
            # the future a direct message to the node that requested the block
            # will be used.
            LOGGER.debug("Responding to block requests: %s",
                         block.get_block().header_signature)
            self._gossip.broadcast_block(block.get_block())

        return HandlerResult(
            status=HandlerStatus.PASS)


class BatchResponderHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip

    def handle(self, identity, message_content):
        gossip_message = network_pb2.GossipBatchRequest()
        gossip_message.ParseFromString(message_content)
        batch = None
        if gossip_message.id_type == "Batch":
            batch = self._responder.check_for_batch(gossip_message.id)

        elif gossip_message.id_type == "Transaction":
            batch = self._responder.check_for_batch_by_transaction(
                gossip_message.id)

        if batch is None:
            self._gossip.broadcast(gossip_message,
                                   validator_pb2.Message.GOSSIP_BATCH_REQUEST)

        else:
            LOGGER.debug("Responding to batch requests %s",
                         batch.header_signature)
            self._gossip.broadcast_batch(batch)

        return HandlerResult(
            status=HandlerStatus.PASS)
