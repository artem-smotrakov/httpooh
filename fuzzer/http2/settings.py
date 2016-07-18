#!/usr/bin/python

import fuzzer.http2.core
from fuzzer.http2.core import Frame

# HTTP/2 Settings frame
# See https://tools.ietf.org/html/rfc7540#section-6.5 for details
class SettingsFrame(Frame):

    def __init__(self):
        # SETTINGS frame type is 0x4
        self.__settings_frame_type = 0x4
        self.__identifier_length = 2
        self.__value_length = 4

        Frame.__init__(self, self.__settings_frame_type)

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
    def encode(self):
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

        return Frame.encode(self, payload)

    def encode_parameter(self, identifier, value):
        parameter = bytearray()
        parameter.extend(self.encode_identifier(identifier))
        parameter.extend(self.encode_value(value))
        return parameter

    def encode_identifier(self, identifier):
        return fuzzer.http2.core.encode_unsigned_integer(identifier, self.__identifier_length)

    def encode_value(self, value):
        return fuzzer.http2.core.encode_unsigned_integer(value, self.__value_length)


# TODO: use DumbHTTP1RequestFuzzer (make a general byte-flipping fuzzer)
class DumbSettingsFuzzer:

    def __init__(self):
        raise Exception('Not implemented yet')

    def next(self):
        raise Exception('Not implemented yet')
