# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from . import process
from fwunit import types
import json


def run(cfg, fwunit_cfg):
    input_rules = {}
    for name, ip_space in cfg['address_spaces'].iteritems():
        if not isinstance(ip_space, list):
            ip_space = [ip_space]
        # look up and load the input's rules
        input = fwunit_cfg[name]['output']
        rules = types.from_jsonable(json.load(open(input))['rules'])
        input_rules[name] = dict(rules=rules, ip_space=ip_space)

    return process.combine(input_rules)
