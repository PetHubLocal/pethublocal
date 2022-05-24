#!/usr/bin/env python3
"""
    Basic logging framework
"""
import logging
import datetime
import json

LEVEL = logging.DEBUG

# Setup Logging framework to log to console without timestamps and log to file with timestamps
log = logging.getLogger(__name__)
log.setLevel(LEVEL)
now = datetime.datetime.now()
fh = logging.FileHandler(f'pethubtest-{now:%Y-%m-%d}.log')
fh.setFormatter(logging.Formatter('%(asctime)s : [%(levelname)5s] : %(message)s'))
log.addHandler(fh)

info = log.info
error = log.error
debug = log.debug
warning = log.warning
exception = log.exception

def jp(jsondata):
    return "Result:\n" + json.dumps(jsondata, indent=4)
