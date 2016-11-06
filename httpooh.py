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

conf = config.Config()
conf.readargs(parser.parse_args())
config.current = conf

if (conf.nofuzzer()):
    raise Exception('No fuzzer enabled')

if conf.server:
    if conf.all:
        fuzzer = http2dumb.DumbHTTP2ServerFuzzer(
                    conf.port, conf.tls, conf.seed,
                    conf.min_ratio, conf.max_ratio, conf.start_test, conf.end_test)
    else:
        fuzzer = http2dumb.DumbHTTP2ServerFuzzer(
                    conf.port, conf.tls, conf.seed,
                    conf.min_ratio, conf.max_ratio, conf.start_test, conf.end_test,
                    conf.common, conf.settings, conf.headers, conf.hpack, conf.priority,
                    conf.rst_stream, conf.data, conf.push_promise, conf.ping, conf.goaway,
                    conf.window_update, conf.continuation)
else:
    if conf.all:
        fuzzer = http2dumb.DumbHTTP2ClientFuzzer(
                    conf.host, conf.port, conf.tls, conf.seed,
                    conf.min_ratio, conf.max_ratio, conf.start_test, conf.end_test)
    else:
        fuzzer = http2dumb.DumbHTTP2ClientFuzzer(
                    conf.host, conf.port, conf.tls, conf.seed,
                    conf.min_ratio, conf.max_ratio, conf.start_test, conf.end_test,
                    conf.common, conf.settings, conf.headers, conf.hpack, conf.priority,
                    conf.rst_stream, conf.data, conf.push_promise, conf.ping, conf.goaway,
                    conf.window_update, conf.continuation)

fuzzer.run()
