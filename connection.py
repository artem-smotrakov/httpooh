#!/usr/bin/python

import socket
import time

class TCPClient:

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
                print 'TCPClient: connect to %s:%d, attempt #%d' % (self.__host, self.__port, attempt)
                try:
                    self.connect()
                except socket.error as msg:
                    print 'TCPClient: could not connect: ', msg
                    time.sleep(self.__delay)
                    continue

            try:
                self.__socket.sendall(data)
                break
            except socket.error as msg:
                print 'TCPClient: could not send data: ', msg
                error = True
                continue

        if attempt == self.__max_attempts:
            raise Exception('Could not connect to remote host %s:%d'
                                % (self.__host, self.__port))

    def receive(self, length = 1024):
        try:
            return self.__socket.recv(length)
        except socket.error as msg:
            print 'TCPClient: could not receive data: ', msg
            return None

    def close(self):
        self.__connected = False
        self.__socket.close()
