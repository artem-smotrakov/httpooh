#!/usr/bin/python

class LinearFuzzer:

    def __init__(self):
        self.fuzzers = []
        self.current = 0

    def add(self, fuzzer):
        self.fuzzers.append(fuzzer)

    def get_state(self):
        raise Exception('No setting states for you!')

    def set_state(self, state):
        raise Exception('No setting states for you!')

    def ready(self):
        raise Exception('No fuzzing for you!')

    def next(self):
        raise Exception('No next states for you!')

    def fuzz(self, subject):
        raise Exception('No fuzzing for you!')


class RequestMethodFuzzer:
    pass


class RequestPathFuzzer:
    pass


class RequestVersionFuzzer:
    pass


class HostnameFuzzer:
    pass