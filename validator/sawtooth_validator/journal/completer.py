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

from sawtooth_validator.journal.block_cache import BlockCache
from sawtooth_validator.journal.block_wrapper import BlockWrapper
from sawtooth_validator.journal.timed_cache import TimedCache
from sawtooth_validator.protobuf.batch_pb2 import Batch
from sawtooth_validator.protobuf.batch_pb2 import BatchList
from sawtooth_validator.protobuf.block_pb2 import Block
from sawtooth_validator.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_validator.protobuf import client_pb2
from sawtooth_validator.protobuf import network_pb2
from sawtooth_validator.protobuf import validator_pb2
from sawtooth_validator.networking.dispatch import Handler
from sawtooth_validator.networking.dispatch import HandlerResult
from sawtooth_validator.networking.dispatch import HandlerStatus

LOGGER = logging.getLogger(__name__)


class Completer(object):
    def __init__(self, block_store):
        self.batch_cache = TimedCache()
        self.block_cache = BlockCache(block_store)
        # The _seen_txns list is a mechanism for tracking which
        # transactions appear in complete batches. This should be
        # replaced with a different mechanism which can query
        # transaction information from the current chain and the
        # pending batch list.
        self._seen_txns = []
        self._incomplete_batches = []
        self._on_block_received = None
        self._on_batch_received = None

    def _check_block(self, block):
        # currently only accepting finalized blocks
        # in the future if the blocks will be built

        if block.previous_block_id not in self.block_cache:
            LOGGER.debug("Block discarded(Missing predecessor): %s",
                         block.header_signature[:8])
            return False
        if len(block.batches) != len(block.header.batch_ids):
            LOGGER.debug("Block discarded(Missing batches): %s",
                         block.header_signature[:8])
            return False

        for i in range(len(block.batches)):
            if block.batches[i].header_signature != block.header.batch_ids[i]:
                LOGGER.debug("Block discarded(Missing batch): %s",
                             block.header_signature[:8])
                return False
        return True

    def _check_batch(self, batch):
        for txn in batch.transactions:
            txn_header = TransactionHeader()
            txn_header.ParseFromString(txn.header)
            for dependency in txn_header.dependencies:
                if dependency not in self._seen_txns:
                    LOGGER.debug("Transaction %s in batch %s has "
                                 "unsatisfied dependency: %s",
                                 txn.header_signature,
                                 batch.header_signature,
                                 dependency)
                    return False
        return True

    def _add_seen_txns(self, batch):
        for txn in batch.transactions:
            self._seen_txns.append(txn.header_signature)

    def _process_incomplete_batches(self):
        for batch in self._incomplete_batches:
            self.add_batch(batch)

    def set_on_block_received(self, on_block_received_func):
        self._on_block_received = on_block_received_func

    def set_on_batch_received(self, on_batch_received_func):
        self._on_batch_received = on_batch_received_func

    def add_block(self, block):
        blkw = BlockWrapper(block)
        if self._check_block(blkw):
            self.block_cache[block.header_signature] = blkw
            self._on_block_received(blkw)

    def add_batch(self, batch):
        if self._check_batch(batch):
            self._add_seen_txns(batch)
            self.batch_cache[batch.header_signature] = batch
            self._on_batch_received(batch)
            if batch in self._incomplete_batches:
                self._incomplete_batches.remove(batch)
            self._process_incomplete_batches()
        else:
            if batch not in self._incomplete_batches:
                self._incomplete_batches.append(batch)


class CompleterBatchListBroadcastHandler(Handler):

    def __init__(self, completer, gossip):
        self._completer = completer
        self._gossip = gossip

    def handle(self, identity, message_content):
        batch_list = BatchList()
        batch_list.ParseFromString(message_content)
        for batch in batch_list.batches:
            self._completer.add_batch(batch)
            self._gossip.broadcast_batch(batch)
        message = client_pb2.ClientBatchSubmitResponse(
            status=client_pb2.ClientBatchSubmitResponse.OK)
        return HandlerResult(
            status=HandlerStatus.RETURN,
            message_out=message,
            message_type=validator_pb2.Message.CLIENT_BATCH_SUBMIT_RESPONSE)


class CompleterGossipHandler(Handler):

    def __init__(self, completer):
        self._completer = completer

    def handle(self, identity, message_content):
        gossip_message = network_pb2.GossipMessage()
        gossip_message.ParseFromString(message_content)
        if gossip_message.content_type == "BLOCK":
            block = Block()
            block.ParseFromString(gossip_message.content)
            self._completer.add_block(block)
        elif gossip_message.content_type == "BATCH":
            batch = Batch()
            batch.ParseFromString(gossip_message.content)
            self._completer.add_batch(batch)
        return HandlerResult(
            status=HandlerStatus.PASS)
