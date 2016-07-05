#!/usr/bin/python

import config

def debug(classname, message):
    if (config.current.debug):
        print('{0}: {1}'.format(classname, message))
