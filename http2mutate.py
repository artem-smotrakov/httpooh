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
#       4. Settings frame (randomly mutate a valid frame) (done, see DumbSettingsFuzzer)
#       5. DATA frame
#       6. HEADERS frame
#       7. PRIORITY frame
#       8. RST_STREAM frame
#       9. PUSH_PROMISE frame
#       10. PING frame
#       11. GOAWAY frame
#       12. WINDOW_UPDATE frame
#       13. CONTINUATION frame


parser = argparse.ArgumentParser()
parser.add_argument('--verbose', help='more logs', action='store_true',
                    default=False)
parser.add_argument('--port', help='port number', type=int, default=80)
parser.add_argument('--host', help='host name', default='localhost')
parser.add_argument('--seed', help='seed for pseudo-random generator', type=int,
                    default=0)
parser.add_argument('--test',
                    help='test range, it can be a number, or an interval "start:end"',
                    default='0')
parser.add_argument('--ratio',
                    help='fuzzing ratio range, it can be a number, or an interval "start:end"',
                    default='0.05')
args = parser.parse_args()

if args.verbose:
    config.current.verbose = True

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

fuzzer = fuzzer.http2.client.DumbHTTP2ClientFuzzer(
                host, port, False, seed, min_ratio, max_ratio, start_test, end_test)
fuzzer.run()
