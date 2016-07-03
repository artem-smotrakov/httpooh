#!/usr/bin/python

import sys
import fuzzer
import socket
import argparse
import config

# TODO: add an option to specify a list of symbols to ignore

parser = argparse.ArgumentParser()
parser.add_argument('--debug', help='enable debug output', action='store_true', default=False)
parser.add_argument('--port', help='port number', type=int, default=80)
parser.add_argument('--host', help='host name', default='localhost')
parser.add_argument('--seed', help='seed for pseudo-random generator', type=int, default=0)
parser.add_argument('--test', help='test range, it can be a number, or an interval "start:end"', default='0')
parser.add_argument('--ratio', help='fuzzing ratio range, it can be a number, or an interval "start:end"', default='0.05')
parser.add_argument('--request', help='path to file with HTTP request to fuzz')
args = parser.parse_args()

if args.debug:
    print('debug output turned on')
    config.current.debug = True
    
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
    raise 'Could not parse --test value, too many colons'
    
parts = args.ratio.split(':')
if len(parts) == 1:
    min_ratio = float(parts[0])
    max_ratio = min_ratio
elif len(parts) == 2:
    min_ratio = float(parts[0])
    max_ratio = float(parts[1])
else:
    raise 'Could not parse --ratio value, too many colons'

if args.request:
    request_file = open(args.request, 'r')
    request = request_file.read()
else:
    request = 'GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n'

fuzzer = fuzzer.MutationalHTTPRequestFuzzer(request, seed, min_ratio, max_ratio, start_test)

test = start_test
while (test <= end_test):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(fuzzer.next())
        data = s.recv(2048)
        print data
    finally:
        s.close
    test += 1
