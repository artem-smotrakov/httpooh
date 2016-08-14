#!/usr/bin/python

import helper
from fuzzer.core import DumbByteArrayFuzzer

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
        self.__verbose('create a frame: write a length ({0:d}): {1:s}'
                       .format(length, helper.bytes2hex(encoded_length)))
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

class DumbCommonFrameFuzzer:

    __default_frame_type = 0x0          # default is DATA frame
    __default_payload_length = 4096     # default length of payload

    def __init__(self, frame_bytes = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        if frame_bytes is None:
            payload = bytearray(DumbCommonFrameFuzzer.__default_payload_length)
            self.__frame_bytes = Frame(DumbCommonFrameFuzzer.__default_frame_type).encode(payload)
        else:
            self.__frame_bytes = frame_bytes
        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__frame_bytes, seed, min_ratio, max_ratio, start_test, ignored_bytes)

    def next(self):
        self.__info('generate a frame')
        return self.__dumb_byte_array_fuzzer.next()

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbCommonFrameFuzzer.__name__, messages[0], messages[1:])
