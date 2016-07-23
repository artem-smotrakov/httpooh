#!/usr/bin/python

import random
import helper

class DumbByteArrayFuzzer:

    def __init__(self, data, seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        # TODO: check if parameters are valid
        self.__start_test = start_test
        self.__data = data
        self.__seed = seed
        self.__min_bytes = round(min_ratio * len(data));
        self.__max_bytes = round(max_ratio * len(data));
        self.__ignored_bytes = ignored_bytes
        self.reset()

    def reset(self):
        self.__test = self.__start_test
        self.__random = random.Random()
        self.__random.seed(self.__seed)
        self.__random_n = random.Random()
        self.__random_position = random.Random()
        self.__random_byte = random.Random()

    def next(self):
        self.debug('next(): test = {0:d}'.format(self.__test))
        fuzzed = self.__data[:]
        seed = self.__random.random() + self.__test
        if self.__min_bytes == self.__max_bytes:
            n = self.__min_bytes
        else:
            self.__random_n.seed(seed)
            n = self.__random_n.randrange(self.__min_bytes, self.__max_bytes);
        self.debug('next(): n = {0:d}'.format(n))
        self.__random_position.seed(seed)
        self.__random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.__random_position.randint(0, len(fuzzed) - 1)
            if self.isignored(fuzzed[pos]):
                self.debug('next(): ignore symbol (pos = {0:d})'.format(pos))
                continue
            b = self.__random_byte.randint(0, 255)
            fuzzed[pos] = b
            i += 1
        self.__test += 1
        self.debug('next(): data: \n{0}'
                   .format(fuzzed.decode('ascii', 'ignore')))
        return fuzzed

    def isignored(self, symbol):
        return symbol in self.__ignored_bytes

    def debug(self, message):
        helper.debug(DumbByteArrayFuzzer.__name__, message)

class DumbAsciiStringFuzzer:

    def __init__(self, string, seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = ()):
        self.__data = bytearray(string, 'ascii', 'ignore')
        self.__ignored_bytes = ignored_symbols
        self.__byte_array_fuzzer = DumbByteArrayFuzzer(
                self.__data, seed, min_ratio, max_ratio, start_test, self.__ignored_bytes)

    def reset(self):
        self.__byte_array_fuzzer.reset()

    def next(self):
        return self.__byte_array_fuzzer.next()

    def debug(self, message):
        helper.debug(DumbAsciiStringFuzzer.__name__, message)
