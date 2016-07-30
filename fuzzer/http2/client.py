#!/usr/bin/python

import textwrap
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

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbHTTP2ClientFuzzer.__name__, messages[0], messages[1:])

    def __info(self, message):
        helper.verbose_with_prefix(DumbHTTP2ClientFuzzer.__name__, message)

    def run(self):
        if self.__is_tls is True:
            raise Exception('TLS connection is not supported yet')
        else:
            self.__client = connection.TCPClient(self.__host, self.__port)

        self.__info('started, test range {0:d}:{1:d}'
                    .format(self.__start_test, self.__end_test))
        test = self.__start_test
        while (test <= self.__end_test):
            if self.__client.isconnected() is False:
                self.__client.connect()
                self.__info('send a client connection preface')
                self.__client.send(fuzzer.http2.core.getclientpreface())
                self.__info('send a valid settings frame')
                settings = SettingsFrame()
                self.__client.send(settings.encode())

            try:
                self.__info('test {0:d}: start'.format(test))
                self.__client.send(self.next())
            except socket.error as msg:
                # move on to next test only if current one was successfully sent out
                # TODO: delay?
                self.__info('test {0:d}: a error occured while sending data, re-connect and send it again: {1}'
                            .format(test, msg))
                continue

            try:
                data = self.__client.receive()
                self.__info('test {0:d}: received reply'.format(test))
                self.__verbose('test {0:d}: received data:'.format(test), helper.bytes2hex(data))
            except socket.error as msg:
                self.__info('test {0:d}: a error occured while receiving data, ignore it: {1}'
                            .format(test, msg))

            test += 1

    def close(self):
        self.__client.close()
