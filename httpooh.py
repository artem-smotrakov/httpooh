#!/usr/bin/python

import argparse
import config
from http2dumb import DumbHttp2ServerTest, DumbHttp2ClientTest

parser = argparse.ArgumentParser()
parser.add_argument('--verbose', help='more logs', action='store_true', default=False)
parser.add_argument('--port',    help='port number', type=int, default=80)
parser.add_argument('--host',    help='host name', default='localhost')
parser.add_argument('--tls',     help='enable TLS', action='store_true')
parser.add_argument('--list',    help='list of available tests', action='store_true')
parser.add_argument('--test',    help='test to run')

# init config
config.current = config.Config(parser)

available_tests = [
    DumbHttp2ServerTest(config.current.host, config.current.port, config.current.tls),
    DumbHttp2ClientTest(config.current.port, config.current.tls)
]

if config.current.list:
    # print out all available tests with a short description
    for test in available_tests:
        print('{0}: {1}'.format(test.name(), test.description()))
elif config.current.test:
    # run specified tests
    raise Exception('No tests for you!')
else:
    raise Exception('What the hell? Run --help and tell me what to do!')
