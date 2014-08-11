# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from . import process
import cPickle as pickle

def run(cfg, fwunit_cfg):
    input_rules = {}
    for name, ranges in cfg['address_spaces'].iteritems():
        if not isinstance(ranges, list):
            ranges = [ranges]
        # look up and load the input's rules
        pkl = fwunit_cfg[name]['output']
        rules = pickle.load(open(pkl))
        input_rules[name] = dict(rules=rules, ranges=ranges)

    return process.combine(input_rules)
