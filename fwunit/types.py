# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# special types that are used within the Pickle file

from fwunit.ip import IPSet, IP
from collections import namedtuple

Rule = namedtuple('Rule', ['src', 'dst', 'app', 'name'])


def ipset_to_jsonable(ipset):
    return [str(pfx) for pfx in ipset]


def to_jsonable(rules):
    return [{'src': ipset_to_jsonable(r.src),
             'dst': ipset_to_jsonable(r.dst),
             'app': r.app,
             'name': r.name}
            for r in rules]


def ipset_from_jsonable(ipset):
    return IPSet([IP(pfx) for pfx in ipset])


def from_jsonable(rules):
    return [Rule(src=ipset_from_jsonable(r['src']),
                 dst=ipset_from_jsonable(r['dst']),
                 app=r['app'],
                 name=r['name'])
            for r in rules]
