#!/usr/bin/python

import helper
import random
import fuzzer.http2.core
from fuzzer.http2.core import Frame

# HTTP/2 WINDOW_UPDATE frame
# See https://tools.ietf.org/html/rfc7540#section-6.9 for details
class WindowUpdateFrame(Frame):

    frame_type = 0x8            # WINDOW_UPDATE frame type is 0x8

    # lengths of fields in WINDOW_UPDATE frame
    __window_size_increment_length = 4

    def __init__(self, stream_id = 0, window_size_increment = 0):
        self.__window_size_increment = window_size_increment
        Frame.__init__(self, WindowUpdateFrame.frame_type, self.flags(), stream_id)

    def payload(self):
        payload = bytearray()

        # write window size increment
        window_size_increment = fuzzer.http2.core.encode_unsigned_integer(
            self.__window_size_increment, WindowUpdateFrame.__window_size_increment_length)
        payload.extend(window_size_increment)

        self.__verbose('write a window update frame:',
                       'window size increment: {0}'.format(self.__window_size_increment))

        return payload

    def flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            WindowUpdateFrame.__name__, messages[0], messages[1:])

# TODO: fuzz WINDOW_UPDATE frame flags even if the spec doesn't define any
class DumbWindowUpdateFuzzer:

    __max_window_size_increment = 2**32 # we want to fuzz one reserved bit

    def __init__(self, seed = 1, min_ratio = 0.01, max_ratio = 0.05, start_test = 0):
        self.__random_window_size_increment = random.Random()
        self.__random_window_size_increment.seed(seed * start_test)

    def next(self, stream_id = 0x0):
        self.__info('generate a window update frame, stream id = {0:d}'.format(stream_id))

        window_size_increment = self.__random_window_size_increment.randint(
            0, DumbWindowUpdateFuzzer.__max_window_size_increment)

        return WindowUpdateFrame(stream_id, window_size_increment).encode()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbWindowUpdateFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbWindowUpdateFuzzer.__name__, messages[0], messages[1:])
