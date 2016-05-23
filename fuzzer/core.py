#!/usr/bin/python

import helper
import random

# TODO: add comments
# TODO: create a test which checks that it generates the same requests 
#       for the same original request, seed and ratios
class MutationalHTTPRequestFuzzer:
    
    
    def __init__(self, request, seed = 0, min_ratio = 0.01, max_ratio = 0.05, start_test = 0, ignored_symbols = ('\r', '\n')):
        # TODO: check if parameters are valid
        self.__start_test = start_test
        self.__request = request
        self.__seed = seed
        self.__min_bytes = round(min_ratio * len(request));
        self.__max_bytes = round(max_ratio * len(request));
        self.__ignored_symbols = ignored_symbols
        self.reset()

    def reset(self):
        self.__test = self.__start_test
        self.__random = random.Random()
        self.__random.seed(self.__seed)
        self.__random.jumpahead(self.__start_test)
        self.__random_n = random.Random()
        self.__random_position = random.Random()
        self.__random_byte = random.Random()
                
    def next(self):
        self.debug('next(): test = %d' % self.__test)
        fuzzed = list(self.__request)
        seed = self.__random.random()
        if self.__min_bytes == self.__max_bytes:
            n = self.__min_bytes
        else:
            self.__random_n.seed(seed)
            n = self.__random_n.randrange(self.__min_bytes, self.__max_bytes);
        self.debug('next(): n = %d' % n)
        self.__random_position.seed(seed)
        self.__random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.__random_position.randint(0, len(self.__request) - 1)
            if self.isignored(fuzzed[pos]):
                self.debug('next(): ignore symbol (pos = %d)' % pos)
                continue
            b = self.__random_byte.randint(0, 255)
            fuzzed[pos] = chr(b)
            i += 1
        self.__test += 1
        request = ''.join(fuzzed)
        self.debug('next(): request: \n%s' % request) 
        return request

    def isignored(self, symbol):
        return symbol in self.__ignored_symbols

    def debug(self, message):
        helper.debug(MutationalHTTPRequestFuzzer.__name__, message)
        