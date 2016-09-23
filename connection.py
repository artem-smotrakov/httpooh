#!/usr/bin/python

import socket
import ssl
import time
import helper

# This is a simple TCP/TLS client which just wraps socket's methods
# It assumes that a connection is closed if any I/O error occured
class Client:

    def __init__(self, host, port, is_tls = False):
        self.__host = host
        self.__port = port
        self.__is_tls = is_tls
        self.__connected = False

    def connect(self):
        self.__connected = False
        self.__verbose('connect to {0}:{1:d}'.format(self.__host, self.__port))
        if self.__is_tls:
            self.__context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.__context.set_alpn_protocols(['h2'])
            self.__socket = self.__context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
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
        helper.verbose('[{0}] {1}'.format(Client.__name__, message))

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

# This is a simple TCP/TLS server which just wraps socket's methods
class Server:

    def __init__(self, port, handler, is_tls = False):
        self.__port = port
        self.__handler = handler
        self.__is_tls = is_tls

    def start(self):
        if self.__is_tls:
            raise Exception('TLS is not supported')
        else:
            self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.bind(('localhost', self.__port))
        self.__server_socket.listen()
        self.__verbose('started server on {0:d} port'.format(self.__port))
        while True:
            # accept connections from outside
            (clientsocket, address) = self.__server_socket.accept()
            self.__verbose('accepted connection')
            self.__handler.handle(clientsocket)

    def close(self):
        self.__server_socket.close()

    def __verbose(self, message):
        helper.verbose('[{0}] {1}'.format(Server.__name__, message))
