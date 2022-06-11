"""
 Pet Hub init
 Copyright (c) 2022, Peter Lambrechtsen (peter@crypt.nz)
"""
# from importlib.metadata import version
# __version__ = version(__name__)
__version__ = '2'
import logging
from logging.handlers import TimedRotatingFileHandler
from .consts import (
    LOGLEVEL,
    LOGNAME
)

def log_renamer(log_name):
    """ Log Renamer """
    base_filename, ext, date = log_name.split(".")
    return f"{base_filename}.{date}.{ext}"

logging.basicConfig(
    level=LOGLEVEL,
)
log = logging.getLogger(__name__)

fh = TimedRotatingFileHandler(LOGNAME, when="midnight", interval=1)
fh.suffix = "%Y-%m-%d"
fh.setFormatter(logging.Formatter('%(asctime)s : [%(levelname)5s] : %(message)s'))
fh.namer = log_renamer
logging.getLogger("").addHandler(fh)

info = log.info
error = log.error
debug = log.debug
warning = log.warning
exception = log.exception
