#!/usr/bin/python

import helper
import random
import socket
import connection

class DumbHTTP2ClientFuzzer:

    def __init__(self, host = "localhost", port = 8080, is_tls = False,
                 seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, end_test = 0):
        # TODO: check if parameters are valid
        self.__host = host
        self.__port = port
        self.__seed = seed
        self.__min_ratio = min_ratio
        self.__max_ratio = max_ratio
        self.__start_test = start_test
        self.__end_test = end_test

        self.__random = random.Random()
        self.__random.seed(self.__seed)
        self.__random.jumpahead(self.__start_test)

        if is_tls is True:
            raise Exception('TLS connection is not supported yet')
        else:
            self.__client = connection.TCPClient(host, port)

    def next(self):
        # TODO: implement
        raise Exception('Not implemented yet')

    def __debug(self, message):
        helper.debug(DumbHTTP2ClientFuzzer.__name__, message)

    def __log(self, message):
        print "%s: %s" % (DumbHTTP2ClientFuzzer.__name__, message)

    def run(self):
        test = self.__start_test
        while (test <= self.__end_test):
            self.__client.send(self.next())
            data = self.__client.receive()
            self.__log('received data: %s' % data)
            test += 1

    def close(self):
        self.__client.close()
