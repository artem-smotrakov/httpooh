#!/usr/bin/python

import helper

# returns a client connection preface sequence
def getclientpreface():
    return bytearray('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'ascii')

def encode_unsigned_integer(number, length):
    return number.to_bytes(length, byteorder='big', signed=False)

# Common HTTP/2 frame
# See https://tools.ietf.org/html/rfc7540#section-4.1 for details
class Frame:

    def __init__(self, frame_type, flags = 0, stream_id = 0):
        # constants
        self.__length_length = 3          # 24 bits
        self.__type_length = 1            # 8 bits
        self.__flags_length = 1           # 8 bits
        self.__stream_id_length = 4 # 32 bits, but the spec defines it
                                          # as an unsigned 31-bit integer,
                                          # and one bit must be set to 0

        self.__frame_type = frame_type
        self.__flags = flags
        self.__stream_id = stream_id

    def encode(self, payload):
        data = bytearray()

        # write 24 bits of payload length
        length = len(payload)
        encoded_length = encode_unsigned_integer(length, self.__length_length)
        self.__verbose('create a frame: write a length ({0:d}): {1:s}'.format(length, helper.bytes2hex(encoded_length)))
        data.extend(encoded_length)

        # write a frame type (8 bits)
        data.extend(encode_unsigned_integer(self.__frame_type, self.__type_length))

        # write flags (8 bits)
        data.extend(encode_unsigned_integer(self.__flags, self.__flags_length))

        # write a stream id expressed as an unsigned 32-bit integer
        # the spec defines a stream id field at an unsigned 31-bit integer,
        # and 1 bit is reserved and must be set to 0
        data.extend(encode_unsigned_integer(self.__stream_id, self.__stream_id_length))

        # write payload
        data.extend(payload)

        return data

    def __verbose(self, *messages):
        helper.verbose_with_prefix(
            Frame.__name__, messages[0])
