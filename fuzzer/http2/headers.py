#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbByteArrayFuzzer

# HTTP/2 Headers frame
# See https://tools.ietf.org/html/rfc7540#section-6.2 for details
class HeadersFrame(Frame):

    frame_type = 0x1            # HEADERS frame type is 0x1

    def __init__(self):
        Frame.__init__(self, HeadersFrame.frame_type)

    def payload(self):
        raise Exception('Not implemented yet')

    def encode(self):
        return Frame.encode(self, self.payload())

class DumbHeadersFuzzer:

    def __init__(self, payload = None, seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        if payload is None:
            raise Exception('Not implemented yet')
        else:
            self.__payload = payload
        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__payload, seed, min_ratio, max_ratio, start_test, ignored_bytes)

    def next(self):
        self.__info('generate a headers frame')
        fuzzed_payload = self.__dumb_byte_array_fuzzer.next()
        return Frame(HeadersFrame.frame_type).encode(fuzzed_payload)

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHeadersFuzzer.__name__, messages[0], messages[1:])
