#!/usr/bin/python

import config

def debug(classname, message):
    if (config.current.debug):
        print('{0}: {1}'.format(classname, message))

def debug_dump(classname, message, data):
    hex_data = ' '.join('{:02x}'.format(b) for b in data)
    debug(classname, "{0:s}:\n{1:s}".format(message, hex_data))
