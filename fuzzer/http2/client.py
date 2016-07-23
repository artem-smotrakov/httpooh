#!/usr/bin/python

import helper
import socket
import connection
import fuzzer.http2.core
from fuzzer.http2.settings import SettingsFrame, DumbSettingsFuzzer

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
        self.__settings_fuzzer = DumbSettingsFuzzer()

    def next(self):
        return self.__settings_fuzzer.next()

    def __debug(self, message):
        helper.debug(DumbHTTP2ClientFuzzer.__name__, message)

    def __log(self, message):
        print('{0}: {1}'.format(DumbHTTP2ClientFuzzer.__name__, message))

    def run(self):
        if self.__is_tls is True:
            raise Exception('TLS connection is not supported yet')
        else:
            self.__client = connection.TCPClient(self.__host, self.__port)

        test = self.__start_test
        while (test <= self.__end_test):
            if self.__client.isconnected() is False:
                self.__log('connect to {0}:{1:d}, and send a client connection preface'
                           .format(self.__host, self.__port))
                self.__client.connect()
                self.__client.send(fuzzer.http2.core.getclientpreface())
                # send a Settings frame
                settings = SettingsFrame()
                self.__client.send(settings.encode())

            try:
                self.__client.send(self.next())
            except socket.error as msg:
                # move on to next test only if current one was successfully sent out
                # TODO: delay?
                self.__log('a error occured while sending data, re-connect and send it again: {0}'.format(msg))
                continue

            try:
                data = self.__client.receive()
                self.__log('received data: {0}'.format(data.decode('ascii', 'ignore')))
            except socket.error as msg:
                self.__log('a error occured while receiving data, ignore it: {0}'.format(msg))

            test += 1

    def close(self):
        self.__client.close()
