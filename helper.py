#!/usr/bin/python

import textwrap
import config
import random

class PapaTest:

    def name(self): return self.__class__.__name__

    def description(self): return 'Here should be a description but someone was too lazy!'

    def info(self, *messages):
        print_with_indent(self.__class__.__name__, messages[0], messages[1:])

    def achtung(self, *messages):
        print_with_indent(self.__class__.__name__, 'Achtung!!! {}'.format(messages[0]), messages[1:])


def verbose(*args):
    if config.current.verbose:
        if len(args) == 0:
            return
        elif len(args) == 1:
            print(args[0])
        elif len(args) == 2:
            verbose_with_prefix(args[0], args[1])
        else:
            verbose_with_indent(args[0], args[1], args[2:])

def print_with_prefix(prefix, message):
    print('[{0:s}] {1}'.format(prefix, message))

def verbose_with_prefix(prefix, message):
    if config.current.verbose:
        print_with_prefix(prefix, message)

def print_with_indent(prefix, first_message, other_messages):
    formatted_prefix = '[{0:s}] '.format(prefix)
    print('{0:s}{1}'.format(formatted_prefix, first_message))
    if len(other_messages) > 0:
        indent = ' ' * len(formatted_prefix)
        wrapper = textwrap.TextWrapper(
            initial_indent=indent, subsequent_indent=indent, width=70)
        for message in other_messages:
            print(wrapper.fill(message))

def verbose_with_indent(prefix, first_message, other_messages):
    if config.current.verbose:
        print_with_indent(prefix, first_message, other_messages)

def bytes2hex(data):
    return ' '.join('{:02x}'.format(b) for b in data)

class DumbByteArrayFuzzer:

    def __init__(self, data, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        # TODO: check if parameters are valid
        self.start_test = start_test
        self.test = start_test
        self.data = data
        self.seed = seed
        self.min_bytes = int(float(min_ratio) * int(len(data)));
        self.max_bytes = int(float(max_ratio) * int(len(data)));
        self.verbose('min bytes to change: {0:d}'.format(self.min_bytes))
        self.verbose('max bytes to change: {0:d}'.format(self.max_bytes))
        self.ignored_bytes = ignored_bytes
        self.reset()

    def set_test(self, test):
        self.test = test

    def reset(self):
        self.test = self.start_test
        self.random = random.Random()
        self.random.seed(self.seed)
        self.random_n = random.Random()
        self.random_position = random.Random()
        self.random_byte = random.Random()

    def next(self):
        fuzzed = self.data[:]
        seed = self.random.random() + self.test
        if self.min_bytes == self.max_bytes:
            n = self.min_bytes
        else:
            self.random_n.seed(seed)
            n = self.random_n.randrange(self.min_bytes, self.max_bytes)
        self.random_position.seed(seed)
        self.random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.random_position.randint(0, len(fuzzed) - 1)
            if self.isignored(fuzzed[pos]):
                continue
            b = self.random_byte.randint(0, 255)
            fuzzed[pos] = b
            i += 1
        self.test += 1
        return fuzzed

    def isignored(self, symbol):
        return symbol in self.ignored_bytes

    def verbose(self, message):
        verbose(DumbByteArrayFuzzer.__name__, message)

class DumbAsciiStringFuzzer:

    def __init__(self, string, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = ()):
        self.data = bytearray(string, 'ascii', 'ignore')
        self.ignored_bytes = ignored_symbols
        self.byte_array_fuzzer = DumbByteArrayFuzzer(
                self.data, seed, min_ratio, max_ratio, start_test, self.ignored_bytes)

    def set_test(self, test):
        self.byte_array_fuzzer.set_test(test)

    def reset(self):
        self.byte_array_fuzzer.reset()

    def next(self):
        return self.byte_array_fuzzer.next()

class DumbDictionaryFuzzer:

    def __init__(self, dictionary, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = (), ignored_keys = (),
                 use_all = False):
        self.start_test = start_test
        self.test = start_test
        self.seed = seed
        self.dictionary = dictionary
        self.ignored_keys = ignored_keys
        self.ignored_symbols = ignored_symbols
        self.min_ratio = min_ratio
        self.max_ratio = max_ratio
        self.use_all = use_all
        self.reset()

    def set_test(self, test):
        self.test = test

    def reset(self):
        self.test = self.start_test
        self.random = random.Random()
        self.random_n = random.Random()
        self.random_position = random.Random()
        self.random_byte = random.Random()
        self.random_item = random.Random()

    def next(self):
        # generate seed for other pseudo-random generators
        self.random.seed(self.seed * self.test)
        seed = self.random.random()

        if self.use_all:
            fuzzed = self.dictionary.copy()
        else:
            self.random_item.seed(seed)
            fuzzed = {}
            for key in self.dictionary:
                if self.random_item.random() >= 0.5:
                    fuzzed[key] = self.dictionary[key]

        total_length = 0
        for key in fuzzed:
            total_length = total_length + len(key) + len(fuzzed[key])

        min_bytes = int(float(self.min_ratio) * int(total_length));
        max_bytes = int(float(self.max_ratio) * int(total_length));

        if min_bytes == max_bytes:
            n = min_bytes
        else:
            self.random_n.seed(seed)
            n = self.random_n.randrange(min_bytes, max_bytes)

        self.random_position.seed(seed)
        self.random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.random_position.randint(0, total_length - 1)

            for key in fuzzed:
                try:
                    if pos < len(key):
                        if self.is_ignored_key(key):
                            continue
                        if self.is_ignored_symbol(key[pos]):
                            continue
                        fuzzed_key = self.fuzz_string(key, pos)
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
                        if self.is_ignored_symbol(value[pos]):
                            continue
                        fuzzed_value = self.fuzz_string(value, pos)
                        fuzzed[key] = fuzzed_value
                        break
                finally:
                    pos = pos - len(value)
                    if pos < 0:
                        break

            i += 1

        self.test += 1
        return fuzzed

    def is_ignored_key(self, key):
        return key in self.ignored_keys

    def is_ignored_symbol(self, symbol):
        return symbol in self.ignored_symbols

    def fuzz_string(self, string, pos):
        if self.is_ignored_symbol(string[pos]):
            return string
        fuzzed = bytearray(string, 'ascii', 'ignore')
        b = self.random_byte.randint(0, 255)
        fuzzed[pos] = b
        return str(fuzzed, 'ascii', 'ignore')

    def verbose(self, message):
        verbose(DumbDictionaryFuzzer.__name__, message)
