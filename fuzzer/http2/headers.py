#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbAsciiStringFuzzer
from hpack import Encoder

# HTTP/2 Headers frame
# See https://tools.ietf.org/html/rfc7540#section-6.2 for details
class HeadersFrame(Frame):

    frame_type = 0x1            # HEADERS frame type is 0x1

    # lengths of fields in HEADERS frame
    __padding_length_length = 1
    __dependency_length = 4
    __weight_length = 1

    # flag definitions
    __end_stream_flag = 0x1
    __end_headers_flag = 0x4
    __padded_flag = 0x8
    __priority_flag = 0x20

    # default values of HEADERS frame
    __default_weight = 32
    __default_padding_length = 8
    __default_dependency = 0

    def __init__(self, stream_id, headers = ()):
        # according to the spec:
        #
        # HEADERS frames MUST be associated with a stream.  If a HEADERS frame
        # is received whose stream identifier field is 0x0, the recipient MUST
        # respond with a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        Frame.__init__(self, HeadersFrame.frame_type, self.flags(), stream_id)
        self.__headers = headers

    def encoded_headers(self):
        return Encoder().encode(self.__headers)

    def payload(self):
        payload = bytearray()

        # write padding length
        padding_length = fuzzer.http2.core.encode_unsigned_integer(
            HeadersFrame.__default_padding_length, HeadersFrame.__padding_length_length)
        payload.extend(padding_length)

        # write no exclusive flag, and no stream dependency
        stream_dependency = fuzzer.http2.core.encode_unsigned_integer(
            HeadersFrame.__default_dependency, HeadersFrame.__dependency_length)
        payload.extend(stream_dependency)

        # write weight
        weight = fuzzer.http2.core.encode_unsigned_integer(
            HeadersFrame.__default_weight, HeadersFrame.__weight_length)
        payload.extend(weight)

        # write header block fragment
        header_block = self.encoded_headers()
        payload.extend(header_block)

        # write padding
        #
        # according to the spec
        #
        # Padding:  Padding octets that contain no application semantic value.
        # Padding octets MUST be set to zero when sending.  A receiver is
        # not obligated to verify padding but MAY treat non-zero padding as
        # a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
        if HeadersFrame.__default_padding_length > 0:
            padding = [0x0] * HeadersFrame.__default_padding_length
            payload.extend(padding)
        else:
            padding = bytearray()

        self.__verbose('write a header frame:',
                       'padding length:    {0}'.format(helper.bytes2hex(padding_length)),
                       'stream dependency: {0}'.format(helper.bytes2hex(stream_dependency)),
                       'weight:            {0}'.format(helper.bytes2hex(weight)),
                       'header block:      ',
                       helper.bytes2hex(header_block),
                       'padding:           ',
                       helper.bytes2hex(padding))

        return payload

    def flags(self):
        return HeadersFrame.__padded_flag | HeadersFrame.__end_headers_flag | HeadersFrame.__priority_flag | HeadersFrame.__end_stream_flag

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            HeadersFrame.__name__, messages[0], messages[1:])

# TODO: fuzz HEADER frame flags
# TODO: add a headers fuzzer which doesn't convert a dict of headers to text,
#       the fuzzer should be able to skip specified headers
class DumbHeadersFuzzer:

    # TODO: add more headers to fuzz
    __default_request_headers = {
            ':scheme' : 'http',
            ':method' : 'GET',
            ':path'   : '/index.html',
            'accept'  : '*/*'
        }

    def __init__(self, headers = None, seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = ()):
        if headers is None:
            self.__headers = DumbHeadersFuzzer.__default_request_headers
        else:
            self.__headers = headers

        ignored_symbols = ignored_symbols + ('\n', '=')
        header_text = self.__convert_headers_to_text(self.__headers)
        self.__verbose('original headers:', str(self.__headers))
        self.__dumb_ascii_string_fuzzer = DumbAsciiStringFuzzer(
            header_text, seed, min_ratio, max_ratio, start_test, ignored_symbols)

    def next(self, stream_id = 1):
        self.__info('generate a headers frame, stream id = {0:d}'.format(stream_id))
        fuzzed_payload = self.__dumb_ascii_string_fuzzer.next().decode('ascii', 'ignore')
        fuzzed_headers = self.__convert_text_to_headers(fuzzed_payload)
        self.__verbose('fuzzed headers:', str(fuzzed_headers))
        return HeadersFrame(stream_id, fuzzed_headers).encode()

    def reset(self):
        self.__dumb_ascii_string_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHeadersFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.print_with_indent(
            DumbHeadersFuzzer.__name__, messages[0], messages[1:])

    def __convert_headers_to_text(self, headers):
        text = ''
        for header in headers:
            text = text + header + '=' + headers[header] + '\n'
        return text

    def __convert_text_to_headers(self, text):
        headers = {}
        for header_string in text.split('\n'):
            parts = header_string.split('=')
            if len(parts) == 1:
                self.__info('skip an incorrect header: {0}'.format(parts[0]))
            elif len(parts) == 2:
                headers[parts[0]] = parts[1]
            else:
                headers[parts[0]] = '='.join(parts[1:])
        return headers
