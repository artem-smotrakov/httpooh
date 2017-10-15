#!/usr/bin/python

# contains configuration, parameters can be accessed as attributes
class Config:

    # init from argparse.ArgumentParser
    def __init__(self, parser):
        self.args = vars(parser.parse_args())

    def __getattr__(self, name):
        return self.args[name]

