#!/usr/bin/python

import helper
import random
import socket

class DumbHTTP2ClientFuzzer:

    def __init__(self, host = "localhost", port = 8080,
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

        # open a socket
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((host, port))

    def next(self):
        # TODO: implement
        raise Exception('Not implemented yet')

    def debug(self, message):
        helper.debug(DumbHTTP2Fuzzer.__name__, message)

    def run(self):
        test = self.__start_test
        while (test <= self.__end_test):
            self.__socket.sendall(self.next())
            data = self.__socket.recv(2048)
            print data
            test += 1

    def close(self):
        self.__socket.close()
