"""Logging: one logger, optional GUI callback, optional log file."""
import logging

OK = 25
logging.addLevelName(OK, "OK")
NAME = "apkporter"


class _CallbackHandler(logging.Handler):
    def __init__(self, cb):
        super().__init__()
        self.cb = cb

    def emit(self, record):
        self.cb(record.levelname, self.format(record))


def setup(callback=None, logfile=None):
    log = logging.getLogger(NAME)
    log.setLevel(logging.DEBUG)
    log.propagate = False
    for h in list(log.handlers):
        h.close()
        log.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S")
    handlers = [_CallbackHandler(callback) if callback else logging.StreamHandler()]
    if logfile:
        handlers.append(logging.FileHandler(logfile, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(fmt)
        log.addHandler(h)
    return log


def get():
    return logging.getLogger(NAME)
