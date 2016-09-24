#!/usr/bin/python

import connection
import helper
from helper import DumbAsciiStringFuzzer

# TODO: add comments
# TODO: create a test which checks that it generates the same requests
#       for the same original request, seed and ratios
# TODO: add end_test parameter
# TODO: add 'HTTP1 request line only fuzzer'
class DumbHTTP1RequestFuzzer:

    def __init__(self, host, port, request, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, end_test = 0, ignored_symbols = ('\r', '\n')):

        if (seed == 0):
            raise Exception('Seed cannot be zero')

        # TODO: check if parameters are valid
        self.__host = host
        self.__port = port
        self.__end_test = end_test
        self.__start_test = start_test
        self.__dumb_ascii_string_fuzzer = DumbAsciiStringFuzzer(
            request, seed, min_ratio, max_ratio, start_test, ignored_symbols)

    def reset(self):
        self.__dumb_ascii_string_fuzzer.reset()

    def next(self):
        return self.__dumb_ascii_string_fuzzer.next()

    def run(self):
        test = self.__start_test
        self.__info('started, test range {0:d}:{1:d}'
                  .format(self.__start_test, self.__end_test))
        while (test <= self.__end_test):
            self.__info('test {0:d}: send'.format(test))
            client = connection.Client(self.__host, self.__port)
            try:
                client.send(self.next())
                data = client.receive()
                self.__info('test {0:d}: received: {1}'.format(test, data.decode('ascii', 'ignore').split('\n', 1)[0]))
            finally:
                client.close()
            test += 1

    def __info(self, message):
        print("[{0}] {1}".format(DumbHTTP1RequestFuzzer.__name__, message))

class Http1RequestLineFuzzer:

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def verbose(self, message):
        helper.verbose(Http1RequestLineFuzzer.__name__, message)

class Http1RequestHeadersFuzzer:

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def verbose(self, message):
        helper.verbose(Http1RequestHeadersFuzzer.__name__, message)

class Http1BodyFuzzer:

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def verbose(self, message):
        helper.verbose(Http1BodyFuzzer.__name__, message)

class Http1RequestFuzzer:

    def __init__(self, http1_request_line_fuzzer, http1_request_headers_fuzzer, http1_body_fuzzer):
        self.__http1_request_line_fuzzer = http1_request_line_fuzzer
        self.__http1_request_headers_fuzzer = http1_request_headers_fuzzer
        self.__http1_body_fuzzer = http1_body_fuzzer

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def verbose(self, message):
        helper.verbose(Http1RequestFuzzer.__name__, message)
