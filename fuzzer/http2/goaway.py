#!/usr/bin/python

import helper
import random
import fuzzer.http2.core
from fuzzer.http2.core import Frame

# HTTP/2 GoAway frame
# See https://tools.ietf.org/html/rfc7540#section-6.8 for details
class GoAwayFrame(Frame):

    frame_type = 0x7            # GOAWAY frame type is 0x7

    # lengths of fields in GOAWAY frame
    __last_stream_id_length = 4
    __error_code_length = 4

    def __init__(self, last_stream_id, error_code, debug_data = bytearray()):
        self.__last_stream_id = last_stream_id
        self.__error_code = error_code
        self.__debug_data = debug_data

        # according to the spec:
        #
        # The GOAWAY frame applies to the connection, not a specific stream.
        # An endpoint MUST treat a GOAWAY frame with a stream identifier other
        # than 0x0 as a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        Frame.__init__(self, GoAwayFrame.frame_type, self.flags(), 0x0)

    def payload(self):
        payload = bytearray()

        # write last stream id
        last_stream_id = fuzzer.http2.core.encode_unsigned_integer(
            self.__last_stream_id, GoAwayFrame.__last_stream_id_length)
        payload.extend(last_stream_id)

        # write error code
        error_code = fuzzer.http2.core.encode_unsigned_integer(
            self.__error_code, GoAwayFrame.__error_code_length)
        payload.extend(error_code)

        if len(self.__debug_data) > 0:
            payload.extend(self.__debug_data)

        self.__verbose('write a goaway frame:',
                       'last stream id: {0}'.format(self.__last_stream_id),
                       'error code:     {0}'.format(self.__error_code),
                       'debug data:     {0}'.format(helper.bytes2hex(self.__debug_data)))

        return payload

    def flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            GoAwayFrame.__name__, messages[0], messages[1:])

# TODO: fuzz GOAWAY frame flags even if the spec doesn't define any
# TODO: fuzz stream ids (even if the spec says it should be 0x0)
class DumbGoAwayFuzzer:

    __max_last_stream_id = 2**32 # we want to fuzz one reserved bit
    __max_error_code = 2**32;
    __max_debug_data_length = 2**12

    def __init__(self, seed = 1, min_ratio = 0.01, max_ratio = 0.05, start_test = 0):
        self.__random_last_stream_id = random.Random()
        self.__random_last_stream_id.seed(seed * start_test)
        self.__random_error_code = random.Random()
        self.__random_error_code.seed(seed * start_test)
        self.__random_debug_data = random.Random()
        self.__random_debug_data.seed(seed * start_test)

    def next(self, stream_id = 0x0):
        self.__info('generate a goaway frame, stream id = {0:d}'.format(stream_id))

        last_stream_id = self.__random_last_stream_id.randint(0, DumbGoAwayFuzzer.__max_last_stream_id)
        error_code = self.__random_error_code.randint(0, DumbGoAwayFuzzer.__max_error_code)

        debug_data = bytearray()
        debug_data_length = self.__random_debug_data.randint(0, DumbGoAwayFuzzer.__max_debug_data_length)
        for i in range(debug_data_length):
            debug_data.append(self.__random_debug_data.randint(0, 255))

        return GoAwayFrame(last_stream_id, error_code, debug_data).encode()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbGoAwayFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbGoAwayFuzzer.__name__, messages[0], messages[1:])
