# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
import json

from . import process
from fwunit import types
from fwunit.ip import IP, IPSet


def get_rules(fwunit_cfg, source_name):
    input = fwunit_cfg[source_name]['output']
    return types.from_jsonable(json.load(open(input))['rules'])

def run(cfg, fwunit_cfg):
    address_spaces = {}
    for name, ip_space in cfg['address_spaces'].iteritems():
        if not isinstance(ip_space, list):
            ip_space = [ip_space]
        address_spaces[name] = IPSet([IP(s) for s in ip_space])

    # Add an "unmanaged" address space for any IP space not mentioned.
    managed_space = IPSet([])
    for sp in address_spaces.itervalues():
        managed_space += sp
    unmanaged_space = IPSet([IP('0.0.0.0/0')]) - managed_space
    if unmanaged_space:
        address_spaces['unmanaged'] = unmanaged_space

    # parse the routes configuration, expanding wildcards
    sources = dict()
    routes = {}
    for src in address_spaces:
        for dst in address_spaces:
            routes[src, dst] = set()
    for srcdest, rulesources in cfg['routes'].iteritems(): 
        if not isinstance(rulesources, list):
            rulesources = [rulesources]
        mo = re.match(r'(.*?) ?(<?)-> ?(.*)', srcdest)
        if not mo:
            raise RuntimeError("invalid route name {:r}".format(srcdest))
        srcs, bidir, dsts = mo.groups()
        # expand wildcards
        srcs = address_spaces.keys() if srcs == '*' else [srcs]
        dsts = address_spaces.keys() if dsts == '*' else [dsts]
        for src in srcs:
            for dst in dsts:
                rt = routes[src, dst]
                for rs in rulesources:
                    rt.add(rs)
                    sources[rs] = None
                if bidir:
                    rt = routes[dst, src]
                    for rs in rulesources:
                        rt.add(rs)

    # load the rules for all of the rule sources referenced
    for rs in sources:
        sources[rs] = get_rules(fwunit_cfg, rs)

    return process.combine(address_spaces, routes, sources)
