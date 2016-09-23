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
from fuzzer.http2.goaway import DumbGoAwayFuzzer
from fuzzer.http2.window_update import DumbWindowUpdateFuzzer
from fuzzer.http2.continuation import DumbContinuationFuzzer

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
        if goaway_fuzzer:
            self.__fuzzers.append(DumbGoAwayFuzzer(
                seed, min_ratio, max_ratio, start_test))
        if window_update_fuzzer:
            self.__fuzzers.append(DumbWindowUpdateFuzzer(
                seed, min_ratio, max_ratio, start_test))
        if continuation_fuzzer:
            self.__fuzzers.append(
                DumbContinuationFuzzer(
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
                self.__info('test {0:d}: received data:'.format(self.__test), helper.bytes2hex(data))
            except OSError as msg:
                self.__info('test {0:d}: a error occured while receiving data, ignore it: {1}'
                            .format(self.__test, msg))

            self.__test += 1

    def close(self):
        self.__server.close()
