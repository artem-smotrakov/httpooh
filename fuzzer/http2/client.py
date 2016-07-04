#!/usr/bin/python

import helper
import random
import socket
import connection
import core
import settings

class DumbHTTP2ClientFuzzer:

    def __init__(self, host = "localhost", port = 8080, is_tls = False,
                 seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, end_test = 0):
        # TODO: check if parameters are valid
        self.__host = host
        self.__port = port
        self.__is_tls = is_tls
        self.__seed = seed
        self.__min_ratio = min_ratio
        self.__max_ratio = max_ratio
        self.__start_test = start_test
        self.__end_test = end_test

        self.__random = random.Random()
        self.__random.seed(self.__seed)
        self.__random.jumpahead(self.__start_test)

    def next(self):
        return 'Like most of life\'s problems, this one can be solved with bending'

    def __debug(self, message):
        helper.debug(DumbHTTP2ClientFuzzer.__name__, message)

    def __log(self, message):
        print "%s: %s" % (DumbHTTP2ClientFuzzer.__name__, message)

    def run(self):
        if self.__is_tls is True:
            raise Exception('TLS connection is not supported yet')
        else:
            self.__client = connection.TCPClient(self.__host, self.__port)

        test = self.__start_test
        while (test <= self.__end_test):
            if self.__client.isconnected() is False:
                self.__log('connect to %s:%d, and send a client connection preface'
                           % (self.__host, self.__port))
                self.__client.connect()
                self.__client.send(core.getclientpreface())
                # TODO: send a valid Settings frame (see RFC 7540)

            try:
                self.__client.send(self.next())
            except socket.error as msg:
                # move on to next test only if current one was successfully sent out
                # TODO: delay?
                self.__log('a error occured while sending data, re-connect and send it again: %s' % msg)
                continue

            try:
                data = self.__client.receive()
                self.__log('received data: %s' % data)
            except socket.error as msg:
                self.__log('a error occured while receiving data, ignore it: %s' % msg)

            test += 1

    def close(self):
        self.__client.close()
