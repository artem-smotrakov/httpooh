#!/usr/bin/python

import base64
import config
import helper
from hpack import Encoder

# returns a client connection preface sequence
def getclientpreface():
    return bytearray('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'ascii')

def encode_unsigned_integer(number, length):
    return number.to_bytes(length, byteorder='big', signed=False)

# Common HTTP/2 frame
# See https://tools.ietf.org/html/rfc7540#section-4.1 for details
class Frame:

    def __init__(self, frame_type, flags = 0, stream_id = 0):
        # constants
        self.length_length = 3          # 24 bits
        self.type_length = 1            # 8 bits
        self.flags_length = 1           # 8 bits
        self.stream_id_length = 4 # 32 bits, but the spec defines it
                                          # as an unsigned 31-bit integer,
                                          # and one bit must be set to 0

        self.frame_type = frame_type
        self.flags = flags
        self.stream_id = stream_id

    def encode(self, payload):
        data = bytearray()

        # write 24 bits of payload length
        length = len(payload)
        encoded_length = encode_unsigned_integer(length, self.length_length)
        self.verbose('create a frame: write a length ({0:d}): {1:s}'
                       .format(length, helper.bytes2hex(encoded_length)))
        data.extend(encoded_length)

        # write a frame type (8 bits)
        data.extend(encode_unsigned_integer(self.frame_type, self.type_length))

        # write flags (8 bits)
        data.extend(encode_unsigned_integer(self.flags, self.flags_length))

        # write a stream id expressed as an unsigned 32-bit integer
        # the spec defines a stream id field at an unsigned 31-bit integer,
        # and 1 bit is reserved and must be set to 0
        data.extend(encode_unsigned_integer(self.stream_id, self.stream_id_length))

        # write payload
        data.extend(payload)

        return data

    def verbose(self, *messages):
        helper.verbose_with_prefix(
            Frame.__name__, messages[0])

# HTTP/2 CONTINUATION frame
# See https://tools.ietf.org/html/rfc7540#section-6.10 for details
class ContinuationFrame(Frame):

    frame_type = 0x9            # CONTINUATION frame type is 0x9

    # flag definitions
    # TODO: flags values are the same for all frames,
    #       need to define it outside frame classes
    __end_headers_flag = 0x4

    def __init__(self, stream_id, headers = ()):
        # according to the spec:
        #
        # CONTINUATION frames MUST be associated with a stream.  If a
        # CONTINUATION frame is received whose stream identifier field is 0x0,
        # the recipient MUST respond with a connection error (Section 5.4.1) of
        # type PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))

        Frame.__init__(self, ContinuationFrame.frame_type, self.get_default_flags(), stream_id)
        self.headers = headers

    def encoded_headers(self):
        return Encoder().encode(self.headers)

    def payload(self):
        payload = bytearray()

        # write header block fragment
        header_block = self.encoded_headers()
        payload.extend(header_block)

        self.verbose('write a continuation frame:',
                       'header block:          ',
                       helper.bytes2hex(header_block))

        return payload

    def get_default_flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            ContinuationFrame.__name__, messages[0], messages[1:])

# HTTP/2 Data frame
# See https://tools.ietf.org/html/rfc7540#section-6.1 for details
class DataFrame(Frame):

    frame_type = 0x0            # DATA frame type is 0x0

    # lengths of fields in DATA frame
    __padding_length_length = 1

    # flag definitions
    __end_stream_flag = 0x1
    __padded_flag = 0x8

    # default values of DATA frame
    __default_padding_length = 32

    def __init__(self, stream_id, data = ()):
        # according to the spec:
        #
        # DATA frames MUST be associated with a stream.  If a DATA frame is
        # received whose stream identifier field is 0x0, the recipient MUST
        # respond with a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        self.data = data
        Frame.__init__(self, DataFrame.frame_type, self.get_default_flags(), stream_id)

    def payload(self):
        payload = bytearray()

        # write padding length
        padding_length = encode_unsigned_integer(
            DataFrame.__default_padding_length, DataFrame.__padding_length_length)
        payload.extend(padding_length)

        # write data
        payload.extend(self.data)

        # write padding
        if DataFrame.__default_padding_length > 0:
            padding = [0x0] * DataFrame.__default_padding_length
            payload.extend(padding)
        else:
            padding = bytearray()

        self.verbose('write a data frame:',
                       'padding length:    {0}'.format(helper.bytes2hex(padding_length)),
                       'data:              ',
                       helper.bytes2hex(self.data),
                       'padding:           ',
                       helper.bytes2hex(padding))

        return payload

    def get_default_flags(self):
        return (DataFrame.__padded_flag | DataFrame.__end_stream_flag)

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            DataFrame.__name__, messages[0], messages[1:])

# HTTP/2 GoAway frame
# See https://tools.ietf.org/html/rfc7540#section-6.8 for details
class GoAwayFrame(Frame):

    frame_type = 0x7            # GOAWAY frame type is 0x7

    # lengths of fields in GOAWAY frame
    __last_stream_id_length = 4
    __error_code_length = 4

    def __init__(self, last_stream_id, error_code, debug_data = bytearray()):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.debug_data = debug_data

        # according to the spec:
        #
        # The GOAWAY frame applies to the connection, not a specific stream.
        # An endpoint MUST treat a GOAWAY frame with a stream identifier other
        # than 0x0 as a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        Frame.__init__(self, GoAwayFrame.frame_type, self.get_default_flags(), 0x0)

    def payload(self):
        payload = bytearray()

        # write last stream id
        last_stream_id = encode_unsigned_integer(
            self.last_stream_id, GoAwayFrame.__last_stream_id_length)
        payload.extend(last_stream_id)

        # write error code
        error_code = encode_unsigned_integer(
            self.error_code, GoAwayFrame.__error_code_length)
        payload.extend(error_code)

        if len(self.debug_data) > 0:
            payload.extend(self.debug_data)

        self.verbose('write a goaway frame:',
                       'last stream id: {0}'.format(self.last_stream_id),
                       'error code:     {0}'.format(self.error_code),
                       'debug data:     {0}'.format(helper.bytes2hex(self.debug_data)))

        return payload

    def get_default_flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            GoAwayFrame.__name__, messages[0], messages[1:])


# HTTP/2 Headers frame
# See https://tools.ietf.org/html/rfc7540#section-6.2 for details
class HeadersFrame(Frame):

    frame_type = 0x1            # HEADERS frame type is 0x1

    # lengths of fields in HEADERS frame
    __padding_length_length = 1
    __dependency_length = 4
    __weight_length = 1

    # flag definitions
    __end_stream_flag = 0x1
    __end_headers_flag = 0x4
    __padded_flag = 0x8
    __priority_flag = 0x20

    # default values of HEADERS frame
    __default_weight = 32
    __default_padding_length = 8
    __default_dependency = 0

    def __init__(self, stream_id, headers = ()):
        # according to the spec:
        #
        # HEADERS frames MUST be associated with a stream.  If a HEADERS frame
        # is received whose stream identifier field is 0x0, the recipient MUST
        # respond with a connection error (Section 5.4.1) of type
        # PROTOCOL_ERROR.
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        Frame.__init__(self, HeadersFrame.frame_type, self.get_default_flags(), stream_id)
        self.headers = headers

    def encoded_headers(self):
        return Encoder().encode(self.headers)

    def payload(self):
        payload = bytearray()

        # write padding length
        padding_length = encode_unsigned_integer(
            HeadersFrame.__default_padding_length, HeadersFrame.__padding_length_length)
        payload.extend(padding_length)

        # write no exclusive flag, and no stream dependency
        stream_dependency = encode_unsigned_integer(
            HeadersFrame.__default_dependency, HeadersFrame.__dependency_length)
        payload.extend(stream_dependency)

        # write weight
        weight = encode_unsigned_integer(
            HeadersFrame.__default_weight, HeadersFrame.__weight_length)
        payload.extend(weight)

        # write header block fragment
        header_block = self.encoded_headers()
        payload.extend(header_block)

        # write padding
        #
        # according to the spec
        #
        # Padding:  Padding octets that contain no application semantic value.
        # Padding octets MUST be set to zero when sending.  A receiver is
        # not obligated to verify padding but MAY treat non-zero padding as
        # a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
        if HeadersFrame.__default_padding_length > 0:
            padding = [0x0] * HeadersFrame.__default_padding_length
            payload.extend(padding)
        else:
            padding = bytearray()

        self.verbose('write a header frame:',
                       'padding length:    {0}'.format(helper.bytes2hex(padding_length)),
                       'stream dependency: {0}'.format(helper.bytes2hex(stream_dependency)),
                       'weight:            {0}'.format(helper.bytes2hex(weight)),
                       'header block:      ',
                       helper.bytes2hex(header_block),
                       'padding:           ',
                       helper.bytes2hex(padding))

        return payload

    def get_default_flags(self):
        return (HeadersFrame.__padded_flag | HeadersFrame.__end_headers_flag |
            HeadersFrame.__priority_flag | HeadersFrame.__end_stream_flag)

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            HeadersFrame.__name__, messages[0], messages[1:])

# HTTP/2 Ping frame
# See https://tools.ietf.org/html/rfc7540#section-6.7 for details
class PingFrame(Frame):

    frame_type = 0x6            # PING frame type is 0x6

    # lengths of fields in PING frame
    opaque_data_length = 8

    # flags
    __ask_flag = 0x1

    def __init__(self, data):
        self.data = data

        # according to the spec:
        #
        # PING frames are not associated with any individual stream.  If a PING
        # frame is received with a stream identifier field value other than
        # 0x0, the recipient MUST respond with a connection error
        # (Section 5.4.1) of type PROTOCOL_ERROR.
        Frame.__init__(self, PingFrame.frame_type, self.get_default_flags(), 0x0)

    def payload(self):
        payload = bytearray()
        payload.extend(self.data)
        self.verbose('write a ping frame:',
                       'data:           {0}'.format(helper.bytes2hex(self.data)))

        return payload

    def get_default_flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            PingFrame.__name__, messages[0], messages[1:])

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
        Frame.__init__(self, PriorityFrame.frame_type, self.get_default_flags(), stream_id)

    def payload(self):
        payload = bytearray()

        # write no exclusive flag, and no stream dependency
        stream_dependency = encode_unsigned_integer(
            PriorityFrame.__default_dependency, PriorityFrame.__dependency_length)
        payload.extend(stream_dependency)

        # write weight
        weight = encode_unsigned_integer(
            PriorityFrame.__default_weight, PriorityFrame.__weight_length)
        payload.extend(weight)

        self.verbose('write a priority frame:',
                       'stream dependency: {0}'.format(helper.bytes2hex(stream_dependency)),
                       'weight:            {0}'.format(helper.bytes2hex(weight)))

        return payload

    def get_default_flags(self):
        # PRIORITY frame doesn't define any flags
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            PriorityFrame.__name__, messages[0], messages[1:])

# HTTP/2 PUSH_PROMISE frame
# See https://tools.ietf.org/html/rfc7540#section-6.6 for details
class PushPromiseFrame(Frame):

    frame_type = 0x5            # PUSH_PROMISE frame type is 0x5

    # lengths of fields in PUSH_PROMISE frame
    __padding_length_length = 1
    __promised_stream_id_length = 4

    # flag definitions
    # TODO: flags values are the same for all frames,
    #       need to define it outside frame classes
    __end_headers_flag = 0x4
    __padded_flag = 0x8

    # default values of PUSH_PROMISE frame
    __default_padding_length = 32

    def __init__(self, stream_id, promised_stream_id, headers = ()):
        # according to the spec:
        #
        # PUSH_PROMISE frames MUST only be sent on a peer-initiated stream that
        # is in either the "open" or "half-closed (remote)" state.  The stream
        # identifier of a PUSH_PROMISE frame indicates the stream it is
        # associated with.  If the stream identifier field specifies the value
        # 0x0, a recipient MUST respond with a connection error (Section 5.4.1)
        # of type PROTOCOL_ERROR.
        if promised_stream_id <= 0:
            raise Exception('invalid promised stream id {0:d}'.format(promised_stream_id))
        self.promised_stream_id = promised_stream_id

        Frame.__init__(self, PushPromiseFrame.frame_type, self.get_default_flags(), stream_id)
        self.headers = headers

    def encoded_headers(self):
        return Encoder().encode(self.headers)

    def payload(self):
        payload = bytearray()

        # write padding length
        padding_length = encode_unsigned_integer(
            PushPromiseFrame.__default_padding_length, PushPromiseFrame.__padding_length_length)
        payload.extend(padding_length)

        # write promised stream id
        promised_stream_id = encode_unsigned_integer(
            self.promised_stream_id, PushPromiseFrame.__promised_stream_id_length)
        payload.extend(promised_stream_id)

        # write header block fragment
        header_block = self.encoded_headers()
        payload.extend(header_block)

        # write padding
        # TODO: should it use different padding length?
        if PushPromiseFrame.__default_padding_length > 0:
            padding = [0x0] * PushPromiseFrame.__default_padding_length
            payload.extend(padding)
        else:
            padding = bytearray()

        self.verbose('write a push promise frame:',
                       'padding length:     {0}'.format(helper.bytes2hex(padding_length)),
                       'promised stream id: {0}'.format(helper.bytes2hex(promised_stream_id)),
                       'header block:          ',
                       helper.bytes2hex(header_block),
                       'padding:               ',
                       helper.bytes2hex(padding))

        return payload

    def get_default_flags(self):
        return PushPromiseFrame.__padded_flag | PushPromiseFrame.__end_headers_flag

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            PushPromiseFrame.__name__, messages[0], messages[1:])

# HTTP/2 RST_STREAM frame
# See https://tools.ietf.org/html/rfc7540#section-6.4 for details
class RstStreamFrame(Frame):

    frame_type = 0x3    # RST_STREAM frame type is 0x3
    max_error_code = 2**32 - 1
    __default_error_code_length = 4

    def __init__(self, stream_id, error_code):
        if stream_id <= 0:
            raise Exception('invalid stream id {0:d}'.format(stream_id))
        if (error_code < 0 or error_code >= RstStreamFrame.max_error_code):
            raise Exception('invalid error code {0:d}'.format(error_code))

        self.error_code = error_code
        self.stream_id = stream_id
        Frame.__init__(self, RstStreamFrame.frame_type, self.get_default_flags(), stream_id)

    def payload(self):
        payload = bytearray()
        payload.extend(encode_unsigned_integer(
            self.error_code, RstStreamFrame.__default_error_code_length))
        return payload

    def encode(self):
        return Frame.encode(self, self.payload())

    def get_default_flags(self):
        # RST_STREAM frame doesn't define any flags
        return 0x0

# HTTP/2 Settings frame
# See https://tools.ietf.org/html/rfc7540#section-6.5 for details
class SettingsFrame(Frame):

    frame_type = 0x4    # SETTINGS frame type is 0x4
    __identifier_length = 2
    __value_length = 4

    def __init__(self):
        Frame.__init__(self, SettingsFrame.frame_type)

        # parameters defined by the spec
        self.settings_header_table_size = 4096      # the initial value recommended by the spec
        self.settings_enable_push = 1               # the initial value recommended by the spec
        self.settings_max_concurrent_streams = 100  # the spec doesn't define the initial value
                                                      # for this parameter, but recommends that
                                                      # this value be no smaller than 100
        self.settings_initial_window_size = 65535   # 2^16-1 octets
                                                      # the initial value recommended by the spec
        self.settings_max_frame_size = 16384        # 2^14 octets
                                                      # the initial value recommended by the spec
        self.settings_max_header_list_size = 65535  # the spec doesn't difine the initial value
                                                      # for this parameter

    def disable_push(self):
        self.settings_enable_push = 0

    def payload(self):
        payload = bytearray()

        # write SETTINGS_HEADER_TABLE_SIZE (0x1) parameter
        payload.extend(self.encode_parameter(0x1, self.settings_header_table_size))

        # write SETTINGS_ENABLE_PUSH (0x2) parameter
        payload.extend(self.encode_parameter(0x2, self.settings_enable_push))

        # write SETTINGS_MAX_CONCURRENT_STREAMS (0x3) parameter
        payload.extend(self.encode_parameter(0x3, self.settings_max_concurrent_streams))

        # write SETTINGS_INITIAL_WINDOW_SIZE (0x4) parameter
        payload.extend(self.encode_parameter(0x4, self.settings_initial_window_size))

        # write SETTINGS_MAX_FRAME_SIZE (0x5) parameter
        payload.extend(self.encode_parameter(0x5, self.settings_max_frame_size))

        # write SETTINGS_MAX_HEADER_LIST_SIZE (0x6) parameter
        payload.extend(self.encode_parameter(0x6, self.settings_max_header_list_size))

        return payload

    def encode(self):
        return Frame.encode(self, self.payload())

    def encode_parameter(self, identifier, value):
        parameter = bytearray()
        parameter.extend(self.encode_identifier(identifier))
        parameter.extend(self.encode_value(value))
        return parameter

    def encode_identifier(self, identifier):
        return encode_unsigned_integer(identifier, SettingsFrame.__identifier_length)

    def encode_value(self, value):
        return encode_unsigned_integer(value, SettingsFrame.__value_length)


# HTTP/2 WINDOW_UPDATE frame
# See https://tools.ietf.org/html/rfc7540#section-6.9 for details
class WindowUpdateFrame(Frame):

    frame_type = 0x8            # WINDOW_UPDATE frame type is 0x8

    # lengths of fields in WINDOW_UPDATE frame
    __window_size_increment_length = 4

    def __init__(self, stream_id = 0, window_size_increment = 0):
        self.window_size_increment = window_size_increment
        Frame.__init__(self, WindowUpdateFrame.frame_type, self.get_default_flags(), stream_id)

    def payload(self):
        payload = bytearray()

        # write window size increment
        window_size_increment = encode_unsigned_integer(
            self.window_size_increment, WindowUpdateFrame.__window_size_increment_length)
        payload.extend(window_size_increment)

        self.verbose('write a window update frame:',
                       'window size increment: {0}'.format(self.window_size_increment))

        return payload

    def get_default_flags(self):
        return 0x0

    def encode(self):
        return Frame.encode(self, self.payload())

    def verbose(self, *messages):
        helper.verbose_with_indent(
            WindowUpdateFrame.__name__, messages[0], messages[1:])


# Example:
#
#    GET / HTTP/1.1
#    Host: server.example.com
#    Connection: Upgrade, HTTP2-Settings
#    Upgrade: h2c
#    HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>
class Http1Upgrade:

    template = '''{} {} {}
Host: {}
Connection: {}
Upgrade: {}
HTTP2-Settings: {}

'''

    def __init__(self):
        self.method = 'GET'
        self.path = '/'
        self.version = 'HTTP/1.1'
        self.host = config.current.host
        self.connection = 'Upgrade, HTTP2-Settings'
        self.upgrade = 'h2' if config.current.tls else 'h2c'
        self.http2settings = SettingsFrame()

    def encode(self):
        return self.get_http_request().encode()

    def get_http_request(self):
        return self.template.format(self.method, self.path, self.version,
                                    self.host,
                                    self.connection,
                                    self.upgrade,
                                    self.get_settings_frame_string())

    def get_settings_frame_string(self):
        return base64.b64encode(self.http2settings.encode()).decode('ascii')

    def set_method(self, method):
        self.method = method

    def set_path(self, path):
        self.path = path

    def set_version(self, version):
        self.version = version

    def set_host(self, host):
        self.host = host

    def __repr__(self):
        return helper.truncate(self.get_http_request())

