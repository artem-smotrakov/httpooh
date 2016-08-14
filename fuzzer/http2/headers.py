#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbDictionaryFuzzer, DumbByteArrayFuzzer
from hpack import Encoder

default_request_headers = {
        ':scheme'                : 'http',
        ':method'                : 'GET',
        ':path'                  : '/index.html',
        'accept'                 : '*/*',
        'Accept-Charset'         : 'utf-8',
        'Accept-Encoding'        : 'gzip, deflate',
        'Accept-Language'        : 'en-US',
        'Accept-Datetime'        : 'Thu, 31 May 2007 20:35:00 GMT',
        'Authorization'          : 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
        'Cache-Control'          : 'no-cache',
        'Connection'             : 'keep-alive',
        'Cookie'                 : '$Version=1; Skin=new;',
        'Content-Length'         : '0',
        'Content-MD5'            : 'Q2hlY2sgSW50ZWdyaXR5IQ==',
        'Content-Type'           : 'application/x-www-form-urlencoded',
        'Date'                   : 'Tue, 15 Nov 1994 08:12:31 GMT',
        'Forwarded'              : ('for=192.0.2.60;proto=http;' +
                                    'by=203.0.113.43 ' +
                                    'Forwarded: for=192.0.2.43, for=198.51.100.17'),
        'From'                   : 'user@example.com',
        'If-Match'               : '"737060cd8c284d8af7ad3082f209582d"',
        'If-Modified-Since'      : 'Sat, 29 Oct 1994 19:43:31 GMT',
        'If-None-Match'          : '"737060cd8c284d8af7ad3082f209582d"',
        'If-Range'               : '"737060cd8c284d8af7ad3082f209582d"',
        'If-Unmodified-Since'    : 'Sat, 29 Oct 1994 19:43:31 GMT',
        'Max-Forwards'           : '10',
        'Origin'                 : 'http://www.example-social-network.com',
        'Pragma'                 : 'no-cache',
        'Proxy-Authorization'    : 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
        'Range'                  : 'bytes=500-999',
        'Referer'                : 'http://en.wikipedia.org/wiki/Main_Page',
        'TE'                     : 'trailers, deflate',
        'User-Agent'             : ('Mozilla/5.0 (X11; Linux x86_64; rv:12.0)' +
                                    ' Gecko/20100101 Firefox/21.0'),
        'Via'                    : '1.0 fred, 1.1 example.com (Apache/1.1)',
        'Warning'                : '199 Miscellaneous warning',
        'X-Requested-With'       : 'XMLHttpRequest',
        'DNT'                    : '1 (Do Not Track Enabled)',
        'X-Forwarded-For'        : 'client1, proxy1, proxy2',
        'X-Forwarded-Host'       : 'en.wikipedia.org:8080',
        'X-Forwarded-Proto'      : 'http',
        'Front-End-Https'        : 'off',
        'X-HTTP-Method-Override' : 'DELETE',
        'X-Att-Deviceid'         : 'GT-P7320/P7320XXLPG',
        'x-wap-profile'          : 'http://wap.samsungmobile.com/uaprof/SGH-I777.xml',
        'Proxy-Connection'       : 'keep-alive',
        'X-Csrf-Token'           : 'i8XNjC4b8KVok4uw5RftR38Wgp2BFwql'
    }


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
        return (HeadersFrame.__padded_flag | HeadersFrame.__end_headers_flag |
            HeadersFrame.__priority_flag | HeadersFrame.__end_stream_flag)

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            HeadersFrame.__name__, messages[0], messages[1:])

# TODO: fuzz HEADER frame flags
# TODO: don't send all headers, but select them randomly
class DumbHeadersFuzzer:

    def __init__(self, headers = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = (),
                 ignored_header_names = ('accept', ':scheme', ':method', ':path')):
        if headers is None:
            self.__headers = default_request_headers
        else:
            self.__headers = headers

        self.__verbose('original headers:', str(self.__headers))
        self.__dumb_dictionary_fuzzer = DumbDictionaryFuzzer(
            self.__headers, seed, min_ratio, max_ratio, start_test,
            ignored_symbols, ignored_header_names)

    def next(self, stream_id = 1):
        self.__info('generate a headers frame, stream id = {0:d}'.format(stream_id))
        fuzzed_headers = self.__dumb_dictionary_fuzzer.next()
        self.__verbose('fuzzed headers:', str(fuzzed_headers))
        return HeadersFrame(stream_id, fuzzed_headers).encode()

    def reset(self):
        self.__dumb_dictionary_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHeadersFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbHeadersFuzzer.__name__, messages[0], messages[1:])

class DumbHPackFuzzer:

    def __init__(self, headers_frame = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0):

        self.__stream_id = 0x1

        if headers_frame is None:
            self.__headers_frame = HeadersFrame(self.__stream_id, default_request_headers)
        else:
            self.__headers_frame = headers_frame

        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__headers_frame.payload(), seed, min_ratio, max_ratio, start_test)

    def next(self):
        fuzzed_payload = self.__dumb_byte_array_fuzzer.next()
        return Frame(HeadersFrame.frame_type, self.__stream_id,
                     self.__headers_frame.flags()).encode(fuzzed_payload)

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHPackFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbHPackFuzzer.__name__, messages[0], messages[1:])
