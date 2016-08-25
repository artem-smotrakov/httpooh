#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbDictionaryFuzzer
from hpack import Encoder

# HTTP/2 CONTINUATION frame
# See https://tools.ietf.org/html/rfc7540#section-6.10 for details
class ContinuationFrame(Frame):

    frame_type = 0x9            # CONTINUATION frame type is 0x9

    # flag definitions
    # TODO: flags values are the same for all frames,
    #       need to define it outside frame classes
    __end_headers_flag = 0x4

    def __init__(self, stream_id, headers = ()):
        # according to the spec:
        #
        # CONTINUATION frames MUST be associated with a stream.  If a
        # CONTINUATION frame is received whose stream identifier field is 0x0,
        # the recipient MUST respond with a connection error (Section 5.4.1) of
        # type PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))

        Frame.__init__(self, ContinuationFrame.frame_type, self.flags(), stream_id)
        self.__headers = headers

    def encoded_headers(self):
        return Encoder().encode(self.__headers)

    def payload(self):
        payload = bytearray()

        # write header block fragment
        header_block = self.encoded_headers()
        payload.extend(header_block)

        self.__verbose('write a continuation frame:',
                       'header block:          ',
                       helper.bytes2hex(header_block))

        return payload

    def flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            ContinuationFrame.__name__, messages[0], messages[1:])

# TODO: fuzz CONTINUATION frame flags
# TODO: don't send all headers, but select them randomly
# TODO: send fuzzed CONTINUATION frames
class DumbContinuationFuzzer:

    def __init__(self, headers = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = (),
                 ignored_header_names = ('accept', ':scheme', ':method', ':path')):
        if headers is None:
            raise Exception('headers not specified')
        self.__headers = headers

        self.__verbose('original headers:', str(self.__headers))
        self.__dumb_dictionary_fuzzer = DumbDictionaryFuzzer(
            self.__headers, seed, min_ratio, max_ratio, start_test,
            ignored_symbols, ignored_header_names)

    def next(self, stream_id = 1, promised_stream_id = 2):
        self.__info('generate a continuation frame, stream id = {0:d}'.format(stream_id))
        fuzzed_headers = self.__dumb_dictionary_fuzzer.next()
        self.__verbose('fuzzed headers:', str(fuzzed_headers))
        return ContinuationFrame(stream_id, fuzzed_headers).encode()

    def reset(self):
        self.__dumb_dictionary_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbContinuationFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbContinuationFuzzer.__name__, messages[0], messages[1:])
