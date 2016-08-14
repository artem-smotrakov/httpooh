#!/usr/bin/python

import helper
import random
import fuzzer.http2.core
from fuzzer.http2.core import Frame

# HTTP/2 RST_STREAM frame
# See https://tools.ietf.org/html/rfc7540#section-6.4 for details
class RstStreamFrame(Frame):

    frame_type = 0x3    # RST_STREAM frame type is 0x3
    max_error_code = 2**32 - 1
    __default_error_code_length = 4

    def __init__(self, stream_id, error_code):
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        if (error_code < 0 or error_code >= RstStreamFrame.max_error_code):
            raise Exception('invalid error code {0:d}'.format(error_code))

        self.__error_code = error_code
        self.__stream_id = stream_id
        Frame.__init__(self, RstStreamFrame.frame_type, self.flags(), stream_id)

    def payload(self):
        payload = bytearray()
        payload.extend(fuzzer.http2.core.encode_unsigned_integer(
            self.__error_code, RstStreamFrame.__default_error_code_length))
        return payload

    def encode(self):
        return Frame.encode(self, self.payload())

    def flags(self):
        # RST_STREAM frame doesn't define any flags
        return 0x0

# TODO: fuzz frame flags even if RST_STREAM frame doesn't define any flags
class DumbRstStreamFuzzer:

    def __init__(self, seed = 1, start_test = 0):
        self.__start_test = start_test
        self.__seed = seed
        self.reset()

    def reset(self):
        self.__test = self.__start_test
        self.__random_byte_error_code = random.Random()

    def next(self, stream_id = 1):
        self.__random_byte_error_code.seed(self.__seed * self.__test)
        error_code = self.__random_byte_error_code.randint(0, RstStreamFrame.max_error_code)
        self.__info('generate an RST_STREAM frame:',
                    'stream id = {0:d}'.format(stream_id),
                    'error code = {0:d}'.format(error_code))
        self.__test += 1
        return RstStreamFrame(stream_id, error_code).encode()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbRstStreamFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbRstStreamFuzzer.__name__, messages[0], messages[1:])
