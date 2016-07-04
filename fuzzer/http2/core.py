#!/usr/bin/python

# returns a client connection preface sequence
def getclientpreface():
    return bytearray('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'ascii')
