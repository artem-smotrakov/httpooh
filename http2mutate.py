#!/usr/bin/python

import sys
import fuzzer.http2
import argparse
import config

# TODO: What can we fuzz?
#       1. HTTP Upgrade request: request line, Host header, Connection header, Upgrade header,
#                                HTTP2-Settings header which contains Settings frame)
#       2. Connection preface (not sure)
#       3. Frames: length, type, flags, stream identifier, payload (random payload)
#                               (done, see DumbCommonFrameFuzzer)
#       4. Settings frame       (done, see DumbSettingsFuzzer)
#       5. DATA frame           (done, see DumbDataFuzzer)
#       6. HEADERS frame        (done, see DumbHeadersFuzzer)
#       7. PRIORITY frame       (done, see DumbPriorityFuzzer)
#       8. RST_STREAM frame     (done, see DumbRstStreamFuzzer)
#       9. PUSH_PROMISE frame
#       10. PING frame
#       11. GOAWAY frame
#       12. WINDOW_UPDATE frame
#       13. CONTINUATION frame
#       14. HPACK fuzzer        (done, see DumbHPackFuzzer)
#
# TODO: take into accoung stream states and flow control
# TODO: fuzzer for clients (browsers)
# TODO: support TLS

parser = argparse.ArgumentParser()
parser.add_argument('--verbose', help='more logs', action='store_true',
                    default=False)
parser.add_argument('--port', help='port number', type=int, default=80)
parser.add_argument('--host', help='host name', default='localhost')
parser.add_argument('--seed', help='seed for pseudo-random generator', type=int,
                    default=1)
parser.add_argument('--test',
                    help='test range, it can be a number, or an interval "start:end"')
parser.add_argument('--ratio',
                    help='fuzzing ratio range, it can be a number, or an interval "start:end"',
                    default='0.05')
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

args = parser.parse_args()

if (not args.common and not args.settings and not args.headers and not args.hpack
        and not args.priority and not args.rst_stream and not args.data
        and not args.push_promise and not args.ping):
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

fuzzer = fuzzer.http2.client.DumbHTTP2ClientFuzzer(
                host, port, False, seed, min_ratio, max_ratio, start_test, end_test,
                args.common, args.settings, args.headers, args.hpack, args.priority,
                args.rst_stream, args.data, args.push_promise, args.ping)
fuzzer.run()
