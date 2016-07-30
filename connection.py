#!/usr/bin/python

import socket
import time
import helper

# TCPClient is a simple TCP client which just wraps socket's methods
# It assumes that a connection is closed if any I/O error occured
class TCPClient:

    def __init__(self, host, port):
        self.__host = host
        self.__port = port
        self.__connected = False

    def connect(self):
        self.__connected = False
        self.__verbose('connect to {0}:{1:d}'.format(self.__host, self.__port))
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.__host, self.__port))
        self.__connected = True

    def send(self, data):
        try:
            if self.__connected is False:
                self.connect()
            self.__socket.sendall(data)
        except socket.error as msg:
            self.__connected = False
            self.__verbose('could not send data: {0}'.format(msg))
            raise

    def receive(self, length = 1024):
        try:
            if self.__connected is False:
                self.connect()
            return self.__socket.recv(length)
        except socket.error as msg:
            self.__connected = False
            self.__verbose('could not receive data: {0}'.format(msg))
            raise

    def isconnected(self):
        return self.__connected

    def close(self):
        self.__connected = False
        self.__socket.close()

    def __verbose(self, message):
        helper.verbose('[{0}] {1}'.format(TCPClient.__name__, message))

# StubbornTCPClient makes multiple attempts to connect and send data
# if an I/O error occured
class StubbornTCPClient:

    def __init__(self, host, port, max_attempts = 5, delay = 3):
        self.__host = host
        self.__port = port
        self.__max_attempts = max_attempts
        self.__delay = delay    # in seconds
        self.__connected = False

    def connect(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.__host, self.__port))
        self.__connected = True;

    def __reconnect(self):
        self.__connected = False
        self.close()
        self.connect()

    def send(self, data):
        attempt = 0
        error = False
        while (attempt < self.__max_attempts):
            attempt += 1

            if self.__connected is False or error is True:
                self.__verbose('connect to {0}:{1:d}, attempt #{2:d}'
                           .format(self.__host, self.__port, attempt))
                try:
                    self.connect()
                except socket.error as msg:
                    self.__verbose('could not connect: {0}'.format(msg))
                    time.sleep(self.__delay)
                    continue

            try:
                self.__socket.sendall(data)
                break
            except socket.error as msg:
                self.__verbose('could not send data: {0}'.format(msg))
                error = True
                continue

        if attempt == self.__max_attempts:
            raise Exception('Could not connect to remote host {0}:{1:d}'
                            .format(self.__host, self.__port))

    def receive(self, length = 1024):
        try:
            return self.__socket.recv(length)
        except socket.error as msg:
            self.__verbose('could not receive data: {0}'.format(msg))
            return None

    def isconnected(self):
        return self.__connected

    def close(self):
        self.__connected = False
        self.__socket.close()

    def __verbose(self, message):
        helper.verbose('[{0}] {1}'.format(StubbornTCPClient.__name__, message))
