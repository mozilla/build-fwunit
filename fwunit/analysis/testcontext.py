# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
from nose.tools import ok_
from fwunit.analysis import config
from fwunit.analysis import sources
from blessings import Terminal
import prettyip

# patch IPy's IPSet representation
prettyip.patch_ipy()

log = logging.getLogger(__name__)
terminal = Terminal()

class TestContext(object):
    def __init__(self, source):
        if not os.path.exists('fwunit.yaml'):
            raise RuntimeError('Tests must be run from the directory containing `fwunit.yaml`')
        cfg = config.load_config('fwunit.yaml')
        self.source = sources.load_source(cfg, source)

    def assertDenies(self, src, dst, apps):
        ok_(self.source.rulesDeny(src, dst, apps))

    def assertPermits(self, src, dst, apps):
        ok_(self.source.rulesPermit(src, dst, apps))

    def sourcesFor(self, dst, app, ignore_sources=None):
        return self.source.sourcesFor(dst, app, ignore_sources=ignore_sources)

    def allApps(self, src, dst, debug=False):
        return self.source.allApps(src, dst, debug=debug)

    def assertAllApps(self, src, dst, apps, debug=False):
        found_apps = self.source.allApps(src, dst, debug=debug)
        if found_apps != set(apps):
            raise AssertionError("got apps %r; expected %r" % (sorted(list(found_apps)), sorted(list(apps))))
