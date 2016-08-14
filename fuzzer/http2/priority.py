#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbByteArrayFuzzer

# HTTP/2 Priority frame
# See https://tools.ietf.org/html/rfc7540#section-6.3 for details
class PriorityFrame(Frame):

    frame_type = 0x2            # PRIORITY frame type is 0x2

    # lengths of fields in PRIORITY frame
    __dependency_length = 4
    __weight_length = 1

    # default values of PRIORITY frame
    __default_weight = 32
    __default_dependency = 0

    def __init__(self, stream_id):
        # according to the spec:
        #
        # The PRIORITY frame always identifies a stream.  If a PRIORITY frame
        # is received with a stream identifier of 0x0, the recipient MUST
        # respond with a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        Frame.__init__(self, PriorityFrame.frame_type, self.flags(), stream_id)

    def payload(self):
        payload = bytearray()

        # write no exclusive flag, and no stream dependency
        stream_dependency = fuzzer.http2.core.encode_unsigned_integer(
            PriorityFrame.__default_dependency, PriorityFrame.__dependency_length)
        payload.extend(stream_dependency)

        # write weight
        weight = fuzzer.http2.core.encode_unsigned_integer(
            PriorityFrame.__default_weight, PriorityFrame.__weight_length)
        payload.extend(weight)

        self.__verbose('write a priority frame:',
                       'stream dependency: {0}'.format(helper.bytes2hex(stream_dependency)),
                       'weight:            {0}'.format(helper.bytes2hex(weight)))

        return payload

    def flags(self):
        # PRIORITY frame doesn't define any flags
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            PriorityFrame.__name__, messages[0], messages[1:])

# TODO: fuzz PRIORITY frame flags (even if PRIORITY frame doesn't define any)
class DumbPriorityFuzzer:

    __default_stream_id = 0x1

    def __init__(self, priority_frame = None, seed = 0, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):

        self.__stream_id = DumbPriorityFuzzer.__default_stream_id

        if priority_frame is None:
            self.__priority_frame = PriorityFrame(self.__stream_id)
        else:
            self.__priority_frame = priority_frame

        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__priority_frame.payload(), seed, min_ratio, max_ratio, start_test, ignored_bytes)

    def next(self, stream_id = __default_stream_id):
        self.__info('generate a priority frame, stream id = {0:d}'.format(stream_id))
        fuzzed_payload = self.__dumb_byte_array_fuzzer.next()
        self.__verbose('fuzzed payload:', str(fuzzed_payload))
        return Frame(PriorityFrame.frame_type).encode(fuzzed_payload)

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbPriorityFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbPriorityFuzzer.__name__, messages[0], messages[1:])
