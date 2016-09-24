#!/usr/bin/python

import sys
import argparse
import config
import http2dumb

# TODO: take into accoung stream states and flow control
# TODO: fuzzer for clients (browsers)

parser = argparse.ArgumentParser()
parser.add_argument('--verbose', help='more logs', action='store_true',
                    default=False)
parser.add_argument('--server', help='start a server', action='store_true')
parser.add_argument('--port', help='port number', type=int, default=80)
parser.add_argument('--host', help='host name', default='localhost')
parser.add_argument('--seed', help='seed for pseudo-random generator', type=int,
                    default=1)
parser.add_argument('--test',
                    help='test range, it can be a number, or an interval "start:end"')
parser.add_argument('--ratio',
                    help='fuzzing ratio range, it can be a number, or an interval "start:end"',
                    default='0.01:0.05')
parser.add_argument('--tls', action='store_true',
                    help='enable TLS')
fuzzers_group = parser.add_argument_group('fuzzers', 'enable fuzzers')
fuzzers_group.add_argument('--common',  action='store_true',
                           help='enable common frame fuzzer')
fuzzers_group.add_argument('--settings', action='store_true',
                           help='enable settings frame fuzzer')
fuzzers_group.add_argument('--headers', action='store_true',
                           help='enable headers frame fuzzer')
fuzzers_group.add_argument('--hpack', action='store_true',
                           help='enable HPACK fuzzer')
fuzzers_group.add_argument('--priority', action='store_true',
                           help='enable priority fuzzer')
fuzzers_group.add_argument('--rst_stream', action='store_true',
                           help='enable RST_STREAM fuzzer')
fuzzers_group.add_argument('--data', action='store_true',
                           help='enable data fuzzer')
fuzzers_group.add_argument('--push_promise', action='store_true',
                           help='enable push promise fuzzer')
fuzzers_group.add_argument('--ping', action='store_true',
                           help='enable ping fuzzer')
fuzzers_group.add_argument('--goaway', action='store_true',
                           help='enable goaway fuzzer')
fuzzers_group.add_argument('--window_update', action='store_true',
                           help='enable window update fuzzer')
fuzzers_group.add_argument('--continuation', action='store_true',
                           help='enable continuation fuzzer')
fuzzers_group.add_argument('--all', action='store_true',
                           help='enable all available fuzzers')

args = parser.parse_args()

if (not args.common and not args.settings and not args.headers and not args.hpack
        and not args.priority and not args.rst_stream and not args.data
        and not args.push_promise and not args.ping and not args.goaway
        and not args.window_update and not args.continuation and not args.all):
    raise Exception('No fuzzer enabled')

if args.verbose:
    config.current.verbose = True

host = args.host
port = args.port
seed = args.seed

if args.test:
    parts = args.test.split(':')
    if len(parts) == 1:
        start_test = int(parts[0])
        end_test = start_test
    elif len(parts) == 2:
        start_test = int(parts[0])
        if parts[1] == '' or parts[1] == 'infinite':
            end_test = float('inf')
        else:
            end_test = int(parts[1])
    else:
        raise Exception('Could not parse --test value, too many colons')
else:
    start_test = 0
    end_test = float('inf')

parts = args.ratio.split(':')
if len(parts) == 1:
    min_ratio = float(parts[0])
    max_ratio = min_ratio
elif len(parts) == 2:
    min_ratio = float(parts[0])
    max_ratio = float(parts[1])
else:
    raise Exception('Could not parse --ratio value, too many colons')

if args.server:
    if args.all:
        fuzzer = http2dumb.DumbHTTP2ServerFuzzer(
                    port, args.tls, seed, min_ratio, max_ratio, start_test, end_test)
    else:
        fuzzer = http2dumb.DumbHTTP2ServerFuzzer(
                    port, args.tls, seed, min_ratio, max_ratio, start_test, end_test,
                    args.common, args.settings, args.headers, args.hpack, args.priority,
                    args.rst_stream, args.data, args.push_promise, args.ping, args.goaway,
                    args.window_update, args.continuation)
else:
    if args.all:
        fuzzer = http2dumb.DumbHTTP2ClientFuzzer(
                    host, port, args.tls, seed, min_ratio, max_ratio, start_test, end_test)
    else:
        fuzzer = http2dumb.DumbHTTP2ClientFuzzer(
                    host, port, args.tls, seed, min_ratio, max_ratio, start_test, end_test,
                    args.common, args.settings, args.headers, args.hpack, args.priority,
                    args.rst_stream, args.data, args.push_promise, args.ping, args.goaway,
                    args.window_update, args.continuation)

fuzzer.run()
