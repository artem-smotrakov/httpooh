#!/usr/bin/python

import socket
import time

# TCPClient is a simple TCP client which just wraps socket's methods
class TCPClient:

    def __init__(self, host, port):
        self.__host = host
        self.__port = port
        self.__connected = False

    def connect(self):
        self.__log('connect to %s:%d' % (self.__host, self.__port))
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.__host, self.__port))

    def send(self, data):
        if self.__connected is False:
            self.connect()
        self.__socket.sendall(data)

    def receive(self, length = 1024):
        return self.__socket.recv(length)

    def close(self):
        self.__connected = False
        self.__socket.close()

    def __log(self, message):
        print "%s: %s" % (TCPClient.__name__, message)

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
                self.__log('connect to %s:%d, attempt #%d'
                           % (self.__host, self.__port, attempt))
                try:
                    self.connect()
                except socket.error as msg:
                    self.__log('could not connect: %s' % msg)
                    time.sleep(self.__delay)
                    continue

            try:
                self.__socket.sendall(data)
                break
            except socket.error as msg:
                self.__log('could not send data: %s' % msg)
                error = True
                continue

        if attempt == self.__max_attempts:
            raise Exception('Could not connect to remote host %s:%d'
                                % (self.__host, self.__port))

    def receive(self, length = 1024):
        try:
            return self.__socket.recv(length)
        except socket.error as msg:
            self.__log('could not receive data: %s' % msg)
            return None

    def close(self):
        self.__connected = False
        self.__socket.close()

    def __log(self, message):
        print "%s: %s" % (StubbornTCPClient.__name__, message)
