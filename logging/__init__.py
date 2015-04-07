# -*- coding: utf-8 -*-
# pylint: disable=W0212
"""Patch for Python Standard Library module `logging'

**Log Forging**

Log Forging is considered an OSWAP `Vulnerability`


Writing unvalidated user input to log files can allow an attacker to forge log
entries or inject malicious content into the logs.

Log forging vulnerabilities occur when:

    * Data enters an application from an untrusted source.
    * The data is written to an application or system log file.

Applications typically use log files to store a history of events or 
transactions for later review, statistics gathering, or debugging. Depending
on the nature of the application, the task of reviewing log files may be 
performed manually on an as-needed basis or automated with a tool that
automatically culls logs for important events or trending information.

Interpretation of the log files may be hindered or misdirected if an attacker
can supply data to the application that is subsequently logged verbatim. In 
the most benign case, an attacker may be able to insert false entries into the
log file by providing the application with input that includes appropriate 
characters. If the log file is processed automatically, the attacker can 
render the file unusable by corrupting the format of the file or injecting 
unexpected characters. A more subtle attack might involve skewing the log file 
statistics. Forged or otherwise, corrupted log files can be used to cover an 
attacker's tracks or even to implicate another party in the commission of a 
malicious act. In the worst case, an attacker may inject code or other 
commands into the log file and take advantage of a vulnerability in the log 
processing utility. 

:Example:

The following web application code attempts to read an integer value from a 
request object. If the value fails to parse as an integer, then the input is 
logged with an error message indicating what happened.

If a user submitted string having the value "twenty-one" for val, the 
following entry is logged:

Attackers can use this same mechanism to insert arbitrary log entries. 

`Reference: <https://www.owasp.org/index.php/Log_Forging>`_

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
