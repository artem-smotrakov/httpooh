#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbByteArrayFuzzer

# HTTP/2 Settings frame
# See https://tools.ietf.org/html/rfc7540#section-6.5 for details
class SettingsFrame(Frame):

    frame_type = 0x4    # SETTINGS frame type is 0x4
    __identifier_length = 2
    __value_length = 4

    def __init__(self):
        Frame.__init__(self, SettingsFrame.frame_type)

        # parameters defined by the spec
        self.__settings_header_table_size = 4096      # the initial value recommended by the spec
        self.__settings_enable_push = 1               # the initial value recommended by the spec
        self.__settings_max_concurrent_streams = 100  # the spec doesn't define the initial value
                                                      # for this parameter, but recommends that
                                                      # this value be no smaller than 100
        self.__settings_initial_window_size = 65535   # 2^16-1 octets
                                                      # the initial value recommended by the spec
        self.__settings_max_frame_size = 16384        # 2^14 octets
                                                      # the initial value recommended by the spec
        self.__settings_max_header_list_size = 65535  # the spec doesn't difine the initial value
                                                      # for this parameter
    def payload(self):
        payload = bytearray()

        # write SETTINGS_HEADER_TABLE_SIZE (0x1) parameter
        payload.extend(self.encode_parameter(0x1, self.__settings_header_table_size))

        # write SETTINGS_ENABLE_PUSH (0x2) parameter
        payload.extend(self.encode_parameter(0x2, self.__settings_enable_push))

        # write SETTINGS_MAX_CONCURRENT_STREAMS (0x3) parameter
        payload.extend(self.encode_parameter(0x3, self.__settings_max_concurrent_streams))

        # write SETTINGS_INITIAL_WINDOW_SIZE (0x4) parameter
        payload.extend(self.encode_parameter(0x4, self.__settings_initial_window_size))

        # write SETTINGS_MAX_FRAME_SIZE (0x5) parameter
        payload.extend(self.encode_parameter(0x5, self.__settings_max_frame_size))

        # write SETTINGS_MAX_HEADER_LIST_SIZE (0x6) parameter
        payload.extend(self.encode_parameter(0x6, self.__settings_max_header_list_size))

        return payload

    def encode(self):
        return Frame.encode(self, self.payload())

    def encode_parameter(self, identifier, value):
        parameter = bytearray()
        parameter.extend(self.encode_identifier(identifier))
        parameter.extend(self.encode_value(value))
        return parameter

    def encode_identifier(self, identifier):
        return fuzzer.http2.core.encode_unsigned_integer(identifier, SettingsFrame.__identifier_length)

    def encode_value(self, value):
        return fuzzer.http2.core.encode_unsigned_integer(value, SettingsFrame.__value_length)

class DumbSettingsFuzzer:

    def __init__(self, payload = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        if payload is None:
            self.__payload = SettingsFrame().payload()  # default settings
        else:
            self.__payload = payload
        self.__dumb_byte_array_fuzzer = DumbByteArrayFuzzer(
            self.__payload, seed, min_ratio, max_ratio, start_test, ignored_bytes)

    def next(self):
        self.__info('generate a settings frame')
        fuzzed_payload = self.__dumb_byte_array_fuzzer.next()
        return Frame(SettingsFrame.frame_type).encode(fuzzed_payload)

    def reset(self):
        self.__dumb_byte_array_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbSettingsFuzzer.__name__, messages[0], messages[1:])
