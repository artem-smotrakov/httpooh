#!/usr/bin/python


def get_substates(state):
    if state[0] != '(':
        raise Exception('What the hell? state should start with )')

    substates = []
    start = 0
    opened = 0
    i = 0
    for c in state:
        if c == '(':
            if opened == 0:
                start = i
            opened += 1
        elif c == ')':
            if opened == 0:
                raise Exception('What the hell? Wrong state: ' + state);
            if opened == 1:
                substates.append(state[start+1:i])
            opened -= 1

    if opened > 0:
        raise Exception('What the hell? Wrong state: ' + state);

    return substates


class LinearFuzzer:

    def __init__(self):
        self.fuzzers = []
        self.index = 0
        self.prefix = 'linear'

    def current(self):
        return self.current()

    def set_prefix(self, prefix):
        self.prefix = prefix

    def add(self, fuzzer):
        self.fuzzers.append(fuzzer)

    def total(self):
        n = 0
        for fuzzer in self.fuzzers:
            n = n + fuzzer.total()
        return n

    def get_state(self):
        state = self.prefix + ':' + str(self.index)
        for fuzzer in self.fuzzers:
            state = state + fuzzer.get_state()
        return state

    def set_state(self, state):
        substates = get_substates(state);
        if len(substates) != len(self.fuzzers):
            raise Exception('Number of substates does not match to number of fuzzers')

        index = 0
        for fuzzer in self.fuzzers:
            fuzzer.set_state(substates[index])
            index += 1

    def ready(self):
        return self.index < len(self.fuzzers) and self.current().ready()

    def reset(self):
        self.index = 0
        for fuzzer in self.fuzzers:
            fuzzer.reset()

    def next(self):
        # try to set next state for the current fuzzer
        if self.current().next():
            return True

        self.current().reset()

        # look for next fuzzer which can be used for fuzzing
        self.index += 1
        while self.index < len(self.fuzzers):
            if self.current().ready():
                return True
            self.index += 1

        return False

    def fuzz(self, subject):
        self.current().fuzz(subject)


class PapaFuzzer:
    pass


class RequestMethodFuzzer:
    pass


class RequestPathFuzzer:
    pass


class RequestVersionFuzzer:
    pass


class HostnameFuzzer:
    pass

