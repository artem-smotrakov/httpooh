#!/usr/bin/python

import sys
import argparse
import config
from http1dumb import DumbHTTP1RequestFuzzer

# TODO: add an option to specify a list of symbols to ignore

parser = argparse.ArgumentParser()
parser.add_argument('--verbose', help='more logs', action='store_true',
                    default=False)
parser.add_argument('--port', help='port number', type=int, default=80)
parser.add_argument('--host', help='host name', default='localhost')
parser.add_argument('--seed', help='seed for pseudo-random generator', type=int,
                    default=1)
parser.add_argument('--test',
                    help='test range, it can be a number, or an interval "start:end"',
                    default='0')
parser.add_argument('--ratio',
                    help='fuzzing ratio range, it can be a number, or an interval "start:end"',
                    default='0.05')
parser.add_argument('--request', help='path to file with HTTP request to fuzz')
args = parser.parse_args()

host = args.host
port = args.port
seed = args.seed

parts = args.test.split(':')
if len(parts) == 1:
    start_test = int(parts[0])
    end_test = start_test
elif len(parts) == 2:
    start_test = int(parts[0])
    end_test = int(parts[1])
else:
    raise Exception('Could not parse --test value, too many colons')

parts = args.ratio.split(':')
if len(parts) == 1:
    min_ratio = float(parts[0])
    max_ratio = min_ratio
elif len(parts) == 2:
    min_ratio = float(parts[0])
    max_ratio = float(parts[1])
else:
    raise Exception('Could not parse --ratio value, too many colons')

if args.request:
    request_file = open(args.request, 'r')
    request = request_file.read()
else:
    request = 'GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n'

fuzzer = DumbHTTP1RequestFuzzer(
            host, port, request, seed, min_ratio, max_ratio, start_test, end_test)
fuzzer.run()
