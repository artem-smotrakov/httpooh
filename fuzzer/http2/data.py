#!/usr/bin/python

import random
import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbByteArrayFuzzer

# HTTP/2 Data frame
# See https://tools.ietf.org/html/rfc7540#section-6.1 for details
class DataFrame(Frame):

    frame_type = 0x0            # DATA frame type is 0x0

    # lengths of fields in DATA frame
    __padding_length_length = 1

    # flag definitions
    __end_stream_flag = 0x1
    __padded_flag = 0x8

    # default values of DATA frame
    __default_padding_length = 32

    def __init__(self, stream_id, data = ()):
        # according to the spec:
        #
        # DATA frames MUST be associated with a stream.  If a DATA frame is
        # received whose stream identifier field is 0x0, the recipient MUST
        # respond with a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        self.__data = data
        Frame.__init__(self, DataFrame.frame_type, self.flags(), stream_id)

    def payload(self):
        payload = bytearray()

        # write padding length
        padding_length = fuzzer.http2.core.encode_unsigned_integer(
            DataFrame.__default_padding_length, DataFrame.__padding_length_length)
        payload.extend(padding_length)

        # write data
        payload.extend(self.__data)

        # write padding
        if DataFrame.__default_padding_length > 0:
            padding = [0x0] * DataFrame.__default_padding_length
            payload.extend(padding)
        else:
            padding = bytearray()

        self.__verbose('write a data frame:',
                       'padding length:    {0}'.format(helper.bytes2hex(padding_length)),
                       'data:              ',
                       helper.bytes2hex(self.__data),
                       'padding:           ',
                       helper.bytes2hex(padding))

        return payload

    def flags(self):
        return (DataFrame.__padded_flag | DataFrame.__end_stream_flag)

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DataFrame.__name__, messages[0], messages[1:])

# TODO: fuzz DATA frame flags
# TODO: don't generate random data, but modify some valid data
#       (data may depend on client/server mode)
class DumbDataFuzzer:

    def __init__(self, data = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = ()):
        if data is None:
            self.__data = bytearray()
            random_byte = random.Random()
            random_byte.seed(seed)
            for i in range(256):
                self.__data.append(random_byte.randint(0, 255))
        else:
            self.__data = data

        self.__verbose('original data:', helper.bytes2hex(self.__data))
        self.__dumb_byte_array_fuzzer_fuzzer = DumbByteArrayFuzzer(
            self.__data, seed, min_ratio, max_ratio, start_test, ignored_symbols)

    def next(self, stream_id = 1):
        self.__info('generate a data frame, stream id = {0:d}'.format(stream_id))
        fuzzed_data = self.__dumb_byte_array_fuzzer_fuzzer.next()
        self.__verbose('fuzzed data:', helper.bytes2hex(fuzzed_data))
        return DataFrame(stream_id, fuzzed_data).encode()

    def reset(self):
        self.__dumb_byte_array_fuzzer_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbDataFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbDataFuzzer.__name__, messages[0], messages[1:])
