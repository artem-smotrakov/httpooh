#!/usr/bin/python

import helper
import random
from fuzzer.http2.core import Frame

# HTTP/2 Ping frame
# See https://tools.ietf.org/html/rfc7540#section-6.7 for details
class PingFrame(Frame):

    frame_type = 0x6            # PING frame type is 0x6

    # lengths of fields in PING frame
    opaque_data_length = 8

    # flags
    __ask_flag = 0x1

    def __init__(self, data):
        self.__data = data

        # according to the spec:
        #
        # PING frames are not associated with any individual stream.  If a PING
        # frame is received with a stream identifier field value other than
        # 0x0, the recipient MUST respond with a connection error
        # (Section 5.4.1) of type PROTOCOL_ERROR.
        Frame.__init__(self, PingFrame.frame_type, self.flags(), 0x0)

    def payload(self):
        payload = bytearray()
        payload.extend(self.__data)
        self.__verbose('write a ping frame:',
                       'data:           {0}'.format(helper.bytes2hex(self.__data)))

        return payload

    def flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            PingFrame.__name__, messages[0], messages[1:])

# TODO: fuzz PING frame flags
# TODO: fuzz length of opaque data
# TODO: fuzz stream ids (even if the spec says it should be 0x0)
class DumbPingFuzzer:

    def __init__(self, seed = 1, min_ratio = 0.01, max_ratio = 0.05, start_test = 0):
        self.__random = random.Random()
        self.__random.seed(seed * start_test)

    def next(self, stream_id = 0x0):
        self.__info('generate a ping frame, stream id = {0:d}'.format(stream_id))
        data = bytearray()
        for i in range(PingFrame.opaque_data_length):
            data.append(self.__random.randint(0, 255))
        self.__verbose('fuzzed data:', helper.bytes2hex(data))
        return PingFrame(data).encode()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbPingFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbPingFuzzer.__name__, messages[0], messages[1:])
