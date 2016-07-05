#!/usr/bin/python

# returns a client connection preface sequence
def getclientpreface():
    return bytearray('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'ascii')

class Frame:

    def __init__(self, payload, frame_type, flags, stream_id = 0):
        self.__payload = payload
        self.__frame_type = frame_type
        self.__flags = flags
        self.__stream_id = stream_id

    def bytes(self):
        raise Exception('Not implemented yet')
