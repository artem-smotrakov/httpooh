#!/usr/bin/python

import textwrap
import helper
import socket
import connection
import fuzzer.http2.core
from fuzzer.http2.core import DumbCommonFrameFuzzer
from fuzzer.http2.settings import SettingsFrame, DumbSettingsFuzzer
from fuzzer.http2.headers import HeadersFrame, DumbHeadersFuzzer, DumbHPackFuzzer
from fuzzer.http2.priority import PriorityFrame, DumbPriorityFuzzer
from fuzzer.http2.rst_stream import DumbRstStreamFuzzer
from fuzzer.http2.data import DumbDataFuzzer
from fuzzer.http2.push_promise import DumbPushPromiseFuzzer
from fuzzer.http2.ping import DumbPingFuzzer

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
                 data_fuzzer = True, push_promise_fuzzer = True, ping_fuzzer = True):

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
            self.__fuzzers.append(
                DumbHeadersFuzzer(
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
            self.__fuzzers.append(
                DumbPushPromiseFuzzer(
                    default_request_headers, seed, min_ratio, max_ratio, start_test))
        if ping_fuzzer:
            self.__fuzzers.append(
                DumbPingFuzzer(seed, min_ratio, max_ratio, start_test))

    def next(self):
        fuzzed_data = self.__fuzzers[self.__next_fuzzer].next()
        self.__next_fuzzer = (self.__next_fuzzer + 1) % len(self.__fuzzers)
        return fuzzed_data

    def __info(self, *messages):
        helper.print_with_indent(
            DumbHTTP2ClientFuzzer.__name__, messages[0], messages[1:])

    def run(self):
        if self.__is_tls is True:
            raise Exception('TLS connection is not supported yet')
        else:
            self.__client = connection.TCPClient(self.__host, self.__port)

        self.__info('started, test range {0}:{1}'
                    .format(self.__start_test, self.__end_test))
        test = self.__start_test
        successfully_sent = True
        while (test <= self.__end_test):
            if self.__client.isconnected() is False:
                self.__client.connect()
                self.__info('send a client connection preface')
                self.__client.send(fuzzer.http2.core.getclientpreface())
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
