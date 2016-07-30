#!/usr/bin/python

import textwrap
import config

def verbose(*args):
    if config.current.verbose:
        if len(args) == 0:
            return
        elif len(args) == 1:
            print(args[0])
        elif len(args) == 2:
            verbose_with_prefix(args[0], args[1])
        else:
            verbose_with_indent(args[0], args[1], args[2:])

def verbose_with_prefix(prefix, message):
    if config.current.verbose:
        print('[{0:s}] {1}'.format(prefix, message))

def verbose_with_indent(prefix, first_message, other_messages):
    if config.current.verbose:
        formatted_prefix = '[{0:s}] '.format(prefix)
        print('{0:s}{1}'.format(formatted_prefix, first_message))
        indent = ' ' * len(formatted_prefix)
        wrapper = textwrap.TextWrapper(
            initial_indent=indent, subsequent_indent=indent, width=70)
        print(wrapper.fill('\n'.join(other_messages)))

def verbose_dump(classname, message, data):
    hex_data = bytes2hex(data)
    verbose(classname, "{0:s}:\n{1:s}".format(message, hex_data))

def bytes2hex(data):
    return ' '.join('{:02x}'.format(b) for b in data)
