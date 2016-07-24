#!/usr/bin/python

import config

def verbose(classname, message):
    if (config.current.verbose):
        print('{0}: {1}'.format(classname, message))

def verbose_dump(classname, message, data):
    hex_data = ' '.join('{:02x}'.format(b) for b in data)
    verbose(classname, "{0:s}:\n{1:s}".format(message, hex_data))
