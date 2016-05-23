#!/usr/bin/python

import config

def debug(classname, message):
    if (config.current.debug): print "%s: %s" % (classname, message)
