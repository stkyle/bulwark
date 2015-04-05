# -*- coding: utf-8 -*-
# pylint: disable=W0212
"""
Log Forging
https://www.owasp.org/index.php/Log_Forging
https://cwe.mitre.org/data/definitions/117.html

"""
from __future__ import absolute_import
from __future__ import print_function
import sys
import time
import logging

PATCH_ON_IMPORT = True


def patch_logging():
    """forces logging to use line numbers if record has multiple lines
    """
    #former_method = logging.Logger._log
    patched_method = _multiline_log
    logging.Logger._log = patched_method
    logging.patched = time.asctime()
    sys.modules['logging'] = logging


def get_fmt_str(logger_obj):
    """ get the format string(s) that a `Logger` object is using
    """
    log_fmts = []
    for hndlr in logger_obj.handlers:
        log_fmts += [hndlr.formatter._fmt]
    return log_fmts


def set_fmt_str(logger_obj, fmt_str):
    """set the format string(s) that a `Logger` object is using
    """
    for hndlr in logger_obj.handlers:
        hndlr.formatter._fmt = fmt_str


def _multiline_log(self, level, msg, args, exc_info=None, extra=None):
    """
    Low-level logging routine which creates a LogRecord and then calls
    all the handlers of this logger to handle the record.
    """
    msg = str(msg)
    msg_list = msg.splitlines()
    n_lines = len(msg_list)
    if n_lines > 1:
        for line_n, message in enumerate(msg_list):
            message = '[%d/%d] %s' % (line_n + 1, n_lines, message)
            msg_list[line_n] = message

    if logging._srcfile:
        # IronPython doesn't track Python frames, so findCaller raises an
        # exception on some versions of IronPython. We trap it here so that
        # IronPython can use logging.
        try:
            fname, lno, func = self.findCaller()
        except ValueError:
            fname, lno, func = "(unknown file)", 0, "(unknown function)"
    else:
        fname, lno, func = "(unknown file)", 0, "(unknown function)"
    if exc_info:
        if not isinstance(exc_info, tuple):
            exc_info = sys.exc_info()
    for msg in msg_list:

        record = self.makeRecord(
            self.name, level, fname, lno, msg, args, exc_info, func, extra)
        # print(record.getMessage())
        self.handle(record)


if PATCH_ON_IMPORT:
    patch_logging()


if __name__ == "__main__":
    print(__doc__)
