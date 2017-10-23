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
        return self.fuzzers[self.index]

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
            state = state + '(' + fuzzer.get_state() + ')'
        return state

    def set_state(self, state):
        substates = get_substates(state)
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
        return self.current().fuzz(subject)


class AbstractFuzzer:

    def __init__(self):
        self.prefix = 'abstract'

    def set_prefix(self, prefix):
        self.prefix = prefix
        return self

    def total(self):
        raise Exception('No totals for you!')

    def get_state(self):
        raise Exception('No states for you!')

    def set_state(self, state):
        raise Exception('No states for you!')

    def ready(self):
        raise Exception('No fuzzing for you!')

    def reset(self):
        raise Exception('No resets for you!')

    def next(self):
        raise Exception('No fuzzing for you!')

    def fuzz(self, subject):
        raise Exception('No fuzzing for you!')


# BoringFuzzer has a specified set of values which it uses for fuzzing
class BoringFuzzer(AbstractFuzzer):

    def __init__(self):
        super().__init__()
        self.action = None
        self.prefix = 'boring_fuzzer'
        self.index = 0
        self.values = []

    def add_values(self, values):
        if isinstance(values, list):
            for value in values:
                self.values.append(value)
        else:
            raise Exception('You are supposed to give me a list!')

        return self

    def set_action(self, action):
        self.action = action

    def total(self):
        return len(self.values)

    def get_state(self):
        return '{}:{}'.format(self.prefix, self.index)

    def set_state(self, state):
        if not state.startswith(self.prefix):
            raise Exception('What the hell? State does not start with "{}"'.format(self.prefix))

        if ':' not in state:
            raise Exception('What the hell? State does not have ":"')

        self.index = int(state[state.index(':'):])

    def ready(self):
        return self.index < len(self.values)

    def reset(self):
        self.index = 0

    def next(self):
        if self.index == len(self.values) - 1:
            return False

        self.index += 1
        return True

    def get_fuzzed_data(self):
        return self.values[self.index]

    def fuzz(self, subject):
        if self.action:
            self.action(subject, self.get_fuzzed_data())
            return subject

        raise Exception('You should have told me how I can fuzz')


class RequestMethodFuzzer(BoringFuzzer):

    def __init__(self):
        super().__init__()
        self.set_prefix('request_method')
        self.set_action(lambda request, fuzzed: request.set_method(fuzzed))
        self.add_values([
            '',
            'X' * 100000,
            'GET\x00'
        ])
        self.add_values([chr(code) for code in range(0, 256)])


class RequestPathFuzzer(BoringFuzzer):

    def __init__(self):
        super().__init__()
        self.set_prefix('request_path')
        self.set_action(lambda request, fuzzed: request.set_path(fuzzed))
        self.add_values([
            '',
            '/x' * 100000,
            '/xxx\x00',
            '/etc/passwd',
            '{}etc/passwd'.format('../' * 20),
            '.',
            '..'
        ])
        self.add_values([chr(code) for code in range(0, 256)])


class RequestVersionFuzzer(BoringFuzzer):

    def __init__(self):
        super().__init__()
        self.set_prefix('request_version')
        self.set_action(lambda request, fuzzed: request.set_version(fuzzed))
        self.add_values([
            '',
            'HTTP',
            'HTTP/',
            'HTTP/1',
            'HTTP/1.'
            'HTTP/1.1\x00',
            'HTTP/100000.1',
            'HTTP/1.100000',
            'H{}P/1.1'.format('T' * 100000)
        ])
        self.add_values([chr(code) for code in range(0, 256)])


class HostnameFuzzer(BoringFuzzer):

    def __init__(self):
        super().__init__()
        self.set_prefix('request_host')
        self.set_action(lambda request, fuzzed: request.set_host(fuzzed))
        self.add_values([
            '',
            '{}.com'.format('x' * 1200),
            '{}com'.format('x.' * 100),
            'жопа.ком'
        ])
        self.add_values([chr(code) for code in range(0, 256)])

