#!/usr/bin/python

import random
import helper

class DumbByteArrayFuzzer:

    def __init__(self, data, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
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
        fuzzed = self.__data[:]
        seed = self.__random.random() + self.__test
        if self.__min_bytes == self.__max_bytes:
            n = self.__min_bytes
        else:
            self.__random_n.seed(seed)
            n = self.__random_n.randrange(self.__min_bytes, self.__max_bytes)
        self.__random_position.seed(seed)
        self.__random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.__random_position.randint(0, len(fuzzed) - 1)
            if self.isignored(fuzzed[pos]):
                continue
            b = self.__random_byte.randint(0, 255)
            fuzzed[pos] = b
            i += 1
        self.__test += 1
        return fuzzed

    def isignored(self, symbol):
        return symbol in self.__ignored_bytes

    def __verbose(self, message):
        helper.verbose(DumbByteArrayFuzzer.__name__, message)

class DumbAsciiStringFuzzer:

    def __init__(self, string, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = ()):
        self.__data = bytearray(string, 'ascii', 'ignore')
        self.__ignored_bytes = ignored_symbols
        self.__byte_array_fuzzer = DumbByteArrayFuzzer(
                self.__data, seed, min_ratio, max_ratio, start_test, self.__ignored_bytes)

    def reset(self):
        self.__byte_array_fuzzer.reset()

    def next(self):
        return self.__byte_array_fuzzer.next()

class DumbDictionaryFuzzer:

    def __init__(self, dictionary, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = (), ignored_keys = ()):
        self.__start_test = start_test
        self.__seed = seed
        self.__dictionary = dictionary
        self.__ignored_keys = ignored_keys
        self.__ignored_symbols = ignored_symbols

        self.__total_length = 0
        for key in self.__dictionary:
            self.__total_length = self.__total_length + len(key) + len(self.__dictionary[key])

        self.__min_bytes = round(min_ratio * self.__total_length);
        self.__max_bytes = round(max_ratio * self.__total_length);

        self.reset()

    def reset(self):
        self.__test = self.__start_test
        self.__random = random.Random()
        self.__random_n = random.Random()
        self.__random_position = random.Random()
        self.__random_byte = random.Random()

    def next(self):
        fuzzed = self.__dictionary.copy()
        self.__random.seed(self.__seed * self.__test)
        seed = self.__random.random()
        if self.__min_bytes == self.__max_bytes:
            n = self.__min_bytes
        else:
            self.__random_n.seed(seed)
            n = self.__random_n.randrange(self.__min_bytes, self.__max_bytes)
        self.__random_position.seed(seed)
        self.__random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.__random_position.randint(0, self.__total_length - 1)

            for key in fuzzed:
                try:
                    if pos < len(key):
                        if self.__is_ignored_key(key):
                            continue
                        print('key = ' + key)
                        print('pos = {0}'.format(pos))
                        if self.__is_ignored_symbol(key[pos]):
                            continue
                        fuzzed_key = self.__fuzz_string(key, pos)
                        value = fuzzed[key]
                        del fuzzed[key]
                        fuzzed[fuzzed_key] = value
                        break
                finally:
                    pos = pos - len(key)
                    if pos < 0:
                        break

                value = fuzzed[key]
                try:
                    if pos < len(value):
                        if self.__is_ignored_symbol(value[pos]):
                            continue
                        fuzzed_value = self.__fuzz_string(value, pos)
                        fuzzed[key] = fuzzed_value
                        break
                finally:
                    pos = pos - len(value)
                    if pos < 0:
                        break

            i += 1

        self.__test += 1
        return fuzzed

    def __is_ignored_key(self, key):
        return key in self.__ignored_keys

    def __is_ignored_symbol(self, symbol):
        return symbol in self.__ignored_symbols

    def __fuzz_string(self, string, pos):
        if self.__is_ignored_symbol(string[pos]):
            return string
        fuzzed = bytearray(string, 'ascii', 'ignore')
        b = self.__random_byte.randint(0, 255)
        fuzzed[pos] = b
        return str(fuzzed, 'ascii', 'ignore')
