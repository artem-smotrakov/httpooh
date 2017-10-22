#!/usr/bin/python

import connection
import socket
from fuzzbase import LinearFuzzer, RequestMethodFuzzer, RequestPathFuzzer, RequestVersionFuzzer, HostnameFuzzer
from helper import AbstractTest
from http2core import Http1Upgrade


class Http1UpgradeTest(AbstractTest):

    def __init__(self, config):
        self.config = config
        self.fuzzer = LinearFuzzer()
        self.fuzzer.add(RequestMethodFuzzer())
        # self.fuzzer.add(RequestPathFuzzer())
        # self.fuzzer.add(RequestVersionFuzzer())
        # self.fuzzer.add(HostnameFuzzer())

    def run(self):
        self.info('start, state: '.format(self.fuzzer.get_state()))
        client = connection.Client(self.config.host, self.config.port, self.config.is_tls)
        while self.fuzzer.ready():
            self.info('state: {}'.format(self.fuzzer.state()))
            client.connect()
            try:
                fuzzed = self.fuzzer.fuzz(Http1Upgrade())
                self.info('send fuzzed request', fuzzed)
                client.send(fuzzed)
                data = self.client.receive()
                self.info('received from server', data)
            except socket.error as msg:
                self.achtung('the following error occurred while sending data: {}'.format(msg))
            finally:
                self.fuzzer.next()
                client.close()
        self.info('finished')

    def state(self, s):
        self.fuzzer.state(s)
