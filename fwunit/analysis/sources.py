# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json

from fwunit import types

_cache = {}

class Source(object):
    """The data from a particular source in fwunit.yaml"""

    def __init__(self, filename):
        self.rules = types.from_jsonable(json.load(open(filename))['rules'])

def load_source(cfg, source):
    """Load the named source.  Sources are cached, so multiple calls with the same name
    will not repeatedly re-load the data from disk."""
    if source not in _cache:
        _cache[source] = Source(cfg[source]['output'])
    return _cache[source]
