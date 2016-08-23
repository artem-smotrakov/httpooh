#!/usr/bin/python

import helper
import fuzzer.http2.core
from fuzzer.http2.core import Frame
from fuzzer.core import DumbDictionaryFuzzer, DumbByteArrayFuzzer
from hpack import Encoder

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
        self.__promised_stream_id = promised_stream_id

        Frame.__init__(self, PushPromiseFrame.frame_type, self.flags(), stream_id)
        self.__headers = headers

    def encoded_headers(self):
        return Encoder().encode(self.__headers)

    def payload(self):
        payload = bytearray()

        # write padding length
        padding_length = fuzzer.http2.core.encode_unsigned_integer(
            PushPromiseFrame.__default_padding_length, PushPromiseFrame.__padding_length_length)
        payload.extend(padding_length)

        # write promised stream id
        promised_stream_id = fuzzer.http2.core.encode_unsigned_integer(
            self.__promised_stream_id, PushPromiseFrame.__promised_stream_id_length)
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

        self.__verbose('write a push promise frame:',
                       'padding length:     {0}'.format(helper.bytes2hex(padding_length)),
                       'promised stream id: {0}'.format(helper.bytes2hex(promised_stream_id)),
                       'header block:          ',
                       helper.bytes2hex(header_block),
                       'padding:               ',
                       helper.bytes2hex(padding))

        return payload

    def flags(self):
        return PushPromiseFrame.__padded_flag | PushPromiseFrame.__end_headers_flag

    def encode(self):
        return Frame.encode(self, self.payload())

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            PushPromiseFrame.__name__, messages[0], messages[1:])

# TODO: fuzz PUSH_PROMISE frame flags
# TODO: don't send all headers, but select them randomly
# TODO: fuzz promised stream ids
# TODO: fuzz padding
class DumbPushPromiseFuzzer:

    def __init__(self, headers = None, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_symbols = (),
                 ignored_header_names = ('accept', ':scheme', ':method', ':path')):
        if headers is None:
            raise Exception('headers not specified')
        self.__headers = headers

        self.__verbose('original headers:', str(self.__headers))
        self.__dumb_dictionary_fuzzer = DumbDictionaryFuzzer(
            self.__headers, seed, min_ratio, max_ratio, start_test,
            ignored_symbols, ignored_header_names)

    def next(self, stream_id = 1, promised_stream_id = 2):
        self.__info('generate a headers frame, stream id = {0:d}'.format(stream_id))
        fuzzed_headers = self.__dumb_dictionary_fuzzer.next()
        self.__verbose('fuzzed headers:', str(fuzzed_headers))
        return PushPromiseFrame(stream_id, promised_stream_id, fuzzed_headers).encode()

    def reset(self):
        self.__dumb_dictionary_fuzzer.reset()

    def __info(self, *messages):
        helper.print_with_indent(
            DumbPushPromiseFuzzer.__name__, messages[0], messages[1:])

    def __verbose(self, *messages):
        helper.verbose_with_indent(
            DumbPushPromiseFuzzer.__name__, messages[0], messages[1:])
