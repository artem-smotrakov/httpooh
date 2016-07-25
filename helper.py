#!/usr/bin/python

import config

def verbose(first, second = None):
    if (config.current.verbose):
        if second is None:
            print(first)
        else:
            print('[{0}]: {1}'.format(first, second))

def verbose_dump(classname, message, data):
    hex_data = ' '.join('{:02x}'.format(b) for b in data)
    verbose(classname, "{0:s}:\n{1:s}".format(message, hex_data))
