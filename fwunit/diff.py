# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.ip import IPPairs
from fwunit.analysis import sources
from blessings import Terminal

terminal = Terminal()


def app_diff(app, left, right):
    left_pairs = IPPairs(*[(r.src, r.dst) for r in left])
    right_pairs = IPPairs(*[(r.src, r.dst) for r in right])
    added = right_pairs - left_pairs
    removed = left_pairs - right_pairs
    for s, d in removed:
        yield ("-", app, s, d)
    for s, d in added:
        yield ("+", app, s, d)

def make_diff(left, right):
    for app in sorted(set(left.rules) | set(right.rules)):
        left_rules = left.rulesForApp(app)
        right_rules = right.rulesForApp(app)
        for diff in app_diff(app, left_rules, right_rules):
            yield diff

def show_diff(cfg, left_name, right_name):
    prefixes = {
        '+': '{t.green}+{t.normal}'.format(t=terminal),
        '-': '{t.red}-{t.normal}'.format(t=terminal),
    }
    for symbol, app, src, dst in make_diff(
        sources.load_source(cfg, left_name),
        sources.load_source(cfg, right_name)):
        print "{pfx} {t.bold_cyan}{app}{t.normal} {t.yellow}{src}{t.normal} " \
              "-> {t.magenta}{dst}{t.normal}".format(
                t=terminal, pfx=prefixes[symbol], app=app, src=src, dst=dst)
