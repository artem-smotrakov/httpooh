#!/usr/bin/python

import helper
from fuzzer.core import DumbAsciiStringFuzzer

# TODO: add comments
# TODO: create a test which checks that it generates the same requests
#       for the same original request, seed and ratios
# TODO: add end_test parameter
# TODO: add 'HTTP1 request line only fuzzer'
class DumbHTTP1RequestFuzzer:

    def __init__(self, request, seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = ('\r', '\n')):
        # TODO: check if parameters are valid
        self.__dumb_ascii_string_fuzzer = DumbAsciiStringFuzzer(
            request, seed, min_ratio, max_ratio, start_test, ignored_symbols)

    def reset(self):
        self.__dumb_ascii_string_fuzzer.reset()

    def next(self):
        return self.__dumb_ascii_string_fuzzer.next()

    def debug(self, message):
        helper.debug(DumbHTTP1RequestFuzzer.__name__, message)


class Http1RequestLineFuzzer:

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def debug(self, message):
        helper.debug(Http1RequestLineFuzzer.__name__, message)

class Http1RequestHeadersFuzzer:

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def debug(self, message):
        helper.debug(Http1RequestHeadersFuzzer.__name__, message)

class Http1BodyFuzzer:

    def next(self):
        raise Exception('Not implemented')

    def count(self):
        raise Exception('Not implemented')

    def getvalid(self):
        raise Exception('Not implemented')

    def debug(self, message):
        helper.debug(Http1BodyFuzzer.__name__, message)

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

    def debug(self, message):
        helper.debug(Http1RequestFuzzer.__name__, message)
