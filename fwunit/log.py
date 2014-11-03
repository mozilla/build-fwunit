# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import logging
from blessings import Terminal

# based on https://gist.githubusercontent.com/exhuma/8147910/raw/3d4ba3802b961e77f3156d73644cca12192ec31f/colourised_log_example.py
class ColoredFormatter(logging.Formatter):

    def __init__(self, terminal, *args, **kwargs):
        super(ColoredFormatter, self).__init__(*args, **kwargs)
        self._terminal = terminal

    def format(self, record):
        output = super(ColoredFormatter, self).format(record)
        if record.levelno >= logging.CRITICAL:
            line_color = self._terminal.bold_yellow_on_red
        elif record.levelno >= logging.ERROR:
            line_color = self._terminal.red
        elif record.levelno >= logging.WARNING:
            line_color = self._terminal.yellow
        elif record.levelno >= logging.INFO:
            line_color = self._terminal.green
        else:
            line_color = self._terminal.white
        return line_color(output)

def setup(verbose):
    terminal = Terminal()
    clifmt = ColoredFormatter(
        terminal,
        '[%(asctime)s] %(message)s')
    root_logger = logging.getLogger()
    clihandler = logging.StreamHandler(sys.stdout)
    clihandler.setFormatter(clifmt)
    root_logger.setLevel(logging.NOTSET if verbose else logging.WARNING)
    root_logger.addHandler(clihandler)
