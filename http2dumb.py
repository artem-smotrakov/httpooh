#!/usr/bin/python

import textwrap
import random
import helper
import socket
import connection
import http2core
from http2core import Frame, SettingsFrame, HeadersFrame, DataFrame
from http2core import ContinuationFrame, WindowUpdateFrame, RstStreamFrame
from http2core import PushPromiseFrame, PingFrame, PriorityFrame, GoAwayFrame
from helper import DumbByteArrayFuzzer, DumbDictionaryFuzzer

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

# TODO: it might be better to use different stream ids
#       because some of them can't be re-used in some cases (see the spec),
#       for example if RST_STREAM frame was received
class DumbHTTP2ClientFuzzer:

    __max_stream_id = 2**31     # 31-bit stream id

    def __init__(self, host = "localhost", port = 8080, is_tls = False,
                 seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, end_test = 0,
                 common_fuzzer = True, settings_fuzzer = True,
                 headers_fuzzer = True, hpack_fuzzer = True,
                 priority_fuzzer = True, rst_stream_fuzzer = True,
                 data_fuzzer = True, push_promise_fuzzer = True,
                 ping_fuzzer = True, goaway_fuzzer = True,
                 window_update_fuzzer = True, continuation_fuzzer = True):

        if (seed == 0):
            raise Exception('Seed cannot be zero')

        # TODO: check if parameters are valid
        self.__host = host
        self.__port = port
        self.__is_tls = is_tls
        self.__seed = seed
        self.__min_ratio = min_ratio
        self.__max_ratio = max_ratio
        self.__start_test = start_test
        self.__end_test = end_test
        self.__fuzzers = list()
        self.__next_fuzzer = 0
        if common_fuzzer:
            self.__fuzzers.append(
                DumbCommonFrameFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if settings_fuzzer:
            self.__fuzzers.append(
                DumbSettingsFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if headers_fuzzer:
            self.__fuzzers.append(DumbHeadersFuzzer(
                default_request_headers, seed, min_ratio, max_ratio, start_test))
        if hpack_fuzzer:
            # TODO: should it use different stream ids?
            headers_frame = HeadersFrame(0x1, default_request_headers)
            self.__fuzzers.append(
                DumbHPackFuzzer(headers_frame, seed, min_ratio, max_ratio, start_test))
        if priority_fuzzer:
            self.__fuzzers.append(
                DumbPriorityFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if data_fuzzer:
            self.__fuzzers.append(
                DumbDataFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if rst_stream_fuzzer:
            self.__fuzzers.append(DumbRstStreamFuzzer(seed, start_test))
        if push_promise_fuzzer:
            self.__fuzzers.append(DumbPushPromiseFuzzer(
                default_request_headers, seed, min_ratio, max_ratio, start_test))
        if ping_fuzzer:
            self.__fuzzers.append(
                DumbPingFuzzer(seed, min_ratio, max_ratio, start_test))
        if goaway_fuzzer:
            self.__fuzzers.append(DumbGoAwayFuzzer(
                seed, min_ratio, max_ratio, start_test))
        if window_update_fuzzer:
            self.__fuzzers.append(DumbWindowUpdateFuzzer(
                seed, min_ratio, max_ratio, start_test))
        if continuation_fuzzer:
            self.__fuzzers.append(DumbContinuationFuzzer(
                default_request_headers, seed, min_ratio, max_ratio, start_test))

    def next(self):
        fuzzed_data = self.__fuzzers[self.__next_fuzzer].next()
        self.__next_fuzzer = (self.__next_fuzzer + 1) % len(self.__fuzzers)
        return fuzzed_data

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHTTP2ClientFuzzer.__name__, messages[0], messages[1:])

    def run(self):
        self.__client = connection.Client(self.__host, self.__port, self.__is_tls)

        self.__info('started, test range {0}:{1}'
                    .format(self.__start_test, self.__end_test))
        test = self.__start_test
        successfully_sent = True
        while (test <= self.__end_test):
            if self.__client.isconnected() is False:
                self.__client.connect()
                self.__info('send a client connection preface')
                self.__client.send(http2core.getclientpreface())
                self.__info('send a valid settings frame')

                # TODO: it can be created once
                settings = SettingsFrame()
                self.__client.send(settings.encode())
                data = self.__client.receive()

            try:
                self.__info('test {0:d}: start'.format(test))
                if successfully_sent:
                    fuzzed_data = self.next()
                    successfully_sent = False
                self.__client.send(fuzzed_data)
                successfully_sent = True
            except socket.error as msg:
                # move on to next test only if current one was successfully sent out
                # TODO: delay?
                self.__info('test {0:d}: a error occured while sending data: {1}'
                            .format(test, msg))
                self.__info('test {0:d}: re-connect'.format(test))
                continue

            try:
                data = self.__client.receive()
                self.__info('test {0:d}: received data:'.format(test), helper.bytes2hex(data))
            except socket.error as msg:
                self.__info('test {0:d}: a error occured while receiving data, ignore it: {1}'
                            .format(test, msg))

            test += 1

    def close(self):
        self.__client.close()

class DumbHTTP2ServerFuzzer:

    __max_stream_id = 2**31     # 31-bit stream id

    def __init__(self, port = 8080, is_tls = False,
                 seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, end_test = 0,
                 common_fuzzer = True, settings_fuzzer = True,
                 headers_fuzzer = True, hpack_fuzzer = True,
                 priority_fuzzer = True, rst_stream_fuzzer = True,
                 data_fuzzer = True, push_promise_fuzzer = True,
                 ping_fuzzer = True, goaway_fuzzer = True,
                 window_update_fuzzer = True, continuation_fuzzer = True):

        if (seed == 0):
            raise Exception('Seed cannot be zero')

        # TODO: check if parameters are valid
        self.__port = port
        self.__is_tls = is_tls
        self.__seed = seed
        self.__min_ratio = min_ratio
        self.__max_ratio = max_ratio
        self.__start_test = start_test
        self.__end_test = end_test
        self.__test = start_test
        self.__fuzzers = list()
        self.__next_fuzzer = 0
        if common_fuzzer:
            self.__fuzzers.append(
                DumbCommonFrameFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if settings_fuzzer:
            self.__fuzzers.append(
                DumbSettingsFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if headers_fuzzer:
            self.__fuzzers.append(DumbHeadersFuzzer(
                default_request_headers, seed, min_ratio, max_ratio, start_test))
        if hpack_fuzzer:
            # TODO: should it use different stream ids?
            headers_frame = HeadersFrame(0x1, default_request_headers)
            self.__fuzzers.append(
                DumbHPackFuzzer(headers_frame, seed, min_ratio, max_ratio, start_test))
        if priority_fuzzer:
            self.__fuzzers.append(
                DumbPriorityFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if data_fuzzer:
            self.__fuzzers.append(
                DumbDataFuzzer(None, seed, min_ratio, max_ratio, start_test))
        if rst_stream_fuzzer:
            self.__fuzzers.append(DumbRstStreamFuzzer(seed, start_test))
        if push_promise_fuzzer:
            self.__fuzzers.append(DumbPushPromiseFuzzer(
                default_request_headers, seed, min_ratio, max_ratio, start_test))
        if ping_fuzzer:
            self.__fuzzers.append(
                DumbPingFuzzer(seed, min_ratio, max_ratio, start_test))
        if goaway_fuzzer:
            self.__fuzzers.append(DumbGoAwayFuzzer(
                seed, min_ratio, max_ratio, start_test))
        if window_update_fuzzer:
            self.__fuzzers.append(DumbWindowUpdateFuzzer(
                seed, min_ratio, max_ratio, start_test))
        if continuation_fuzzer:
            self.__fuzzers.append(DumbContinuationFuzzer(
                default_request_headers, seed, min_ratio, max_ratio, start_test))

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHTTP2ServerFuzzer.__name__, messages[0], messages[1:])

    def run(self):
        self.__info('started, test range {0}:{1}'
                    .format(self.__start_test, self.__end_test))
        self.__server = connection.Server(self.__port, self, self.__is_tls)
        self.__server.start()

    # TODO: create a wrapper for socket read/write/connected operations (use it here instead of socket)
    def handle(self, socket):
        self.__info('send a valid settings frame')

        # TODO: it can be created once
        settings = SettingsFrame()

        # TODO: hack for hghtt2, the spec recommends to enable push, but nghttp2 client doesn't work with it
        #       can it be configured in command line?
        settings.disable_push()

        socket.send(settings.encode())
        data = socket.recv(1024)

        while (self.__test <= self.__end_test):
            try:
                self.__info('test {0:d}: start'.format(self.__test))
                fuzzer = self.__fuzzers[self.__next_fuzzer]
                fuzzer.set_test(self.__test)
                fuzzed_data = fuzzer.next()
                self.__next_fuzzer = (self.__next_fuzzer + 1) % len(self.__fuzzers)
                socket.sendall(fuzzed_data)
            except OSError as msg:
                self.__info('test {0:d}: a error occured while sending data: {1}'
                            .format(self.__test, msg))
                self.__info('test {0:d}: will be run again '.format(self.__test))
                break

            try:
                data = socket.recv(1024)
                self.__info('test {0:d}: received data:'
                            .format(self.__test), helper.bytes2hex(data))
            except OSError as msg:
                self.__info('test {0:d}: a error occured while receiving data, ignore it: {1}'
                            .format(self.__test, msg))

            self.__test += 1

    def close(self):
        self.__server.close()

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

        last_stream_id = self.__random_last_stream_id.randint(
            0, DumbGoAwayFuzzer.__max_last_stream_id)
        error_code = self.__random_error_code.randint(
            0, DumbGoAwayFuzzer.__max_error_code)

        debug_data = bytearray()
        debug_data_length = self.__random_debug_data.randint(
            0, DumbGoAwayFuzzer.__max_debug_data_length)
        for i in range(debug_data_length):
            debug_data.append(self.__random_debug_data.randint(0, 255))

        return GoAwayFrame(last_stream_id, error_code, debug_data).encode()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbGoAwayFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbGoAwayFuzzer.__name__, messages[0], messages[1:])

# TODO: fuzz HEADER frame flags
# TODO: don't send all headers, but select them randomly
# TODO: send fuzzed CONTINUATION frames
class DumbHeadersFuzzer:

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
            raise Exception('headers frame not specified')
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

# TODO: fuzz PRIORITY frame flags (even if PRIORITY frame doesn't define any)
class DumbPriorityFuzzer:

    __default_stream_id = 0x1

    def __init__(self, priority_frame = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):

        self.__stream_id = DumbPriorityFuzzer.__default_stream_id

        if priority_frame is None:
            self.__priority_frame = PriorityFrame(self.__stream_id)
        else:
            self.__priority_frame = priority_frame

        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__priority_frame.payload(), seed, min_ratio, max_ratio, start_test, ignored_bytes)

    def next(self, stream_id = __default_stream_id):
        self.__info('generate a priority frame, stream id = {0:d}'.format(stream_id))
        fuzzed_payload = self.__dumb_byte_array_fuzzer.next()
        self.__verbose('fuzzed payload:', str(fuzzed_payload))
        return Frame(PriorityFrame.frame_type).encode(fuzzed_payload)

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbPriorityFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbPriorityFuzzer.__name__, messages[0], messages[1:])

# TODO: fuzz PUSH_PROMISE frame flags
# TODO: don't send all headers, but select them randomly
# TODO: fuzz promised stream ids
# TODO: fuzz padding
# TODO: send fuzzed CONTINUATION frames
class DumbPushPromiseFuzzer:

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
        self.__info('generate a headers frame, stream id = {0:d}'.format(stream_id))
        fuzzed_headers = self.__dumb_dictionary_fuzzer.next()
        self.__verbose('fuzzed headers:', str(fuzzed_headers))
        return PushPromiseFrame(stream_id, promised_stream_id, fuzzed_headers).encode()

    def reset(self):
        self.__dumb_dictionary_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbPushPromiseFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbPushPromiseFuzzer.__name__, messages[0], messages[1:])

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

class DumbSettingsFuzzer:

    def __init__(self, payload = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        if payload is None:
            self.__payload = SettingsFrame().payload()  # default settings
        else:
            self.__payload = payload
        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__payload, seed, min_ratio, max_ratio, start_test, ignored_bytes)

    def set_test(self, test):
        self.__dumb_byte_array_fuzzer.set_test(test)

    def next(self):
        self.__info('generate a settings frame')
        fuzzed_payload = self.__dumb_byte_array_fuzzer.next()
        return Frame(SettingsFrame.frame_type).encode(fuzzed_payload)

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbSettingsFuzzer.__name__, messages[0], messages[1:])

# TODO: fuzz WINDOW_UPDATE frame flags even if the spec doesn't define any
class DumbWindowUpdateFuzzer:

    __max_window_size_increment = 2**32 # we want to fuzz one reserved bit

    def __init__(self, seed = 1, min_ratio = 0.01, max_ratio = 0.05, start_test = 0):
        self.__random_window_size_increment = random.Random()
        self.__random_window_size_increment.seed(seed * start_test)

    def next(self, stream_id = 0x0):
        self.__info('generate a window update frame, stream id = {0:d}'
                    .format(stream_id))

        window_size_increment = self.__random_window_size_increment.randint(
            0, DumbWindowUpdateFuzzer.__max_window_size_increment)

        return WindowUpdateFrame(stream_id, window_size_increment).encode()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbWindowUpdateFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbWindowUpdateFuzzer.__name__, messages[0], messages[1:])