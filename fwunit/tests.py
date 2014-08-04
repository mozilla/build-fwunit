# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import cPickle as pickle
import logging
from fwunit.ip import IP, IPSet, IPPairs
from nose.tools import ok_

log = logging.getLogger(__name__)

def _ipset(ip):
    if isinstance(ip, basestring):
        ip = IP(ip)
    if isinstance(ip, IP):
        ip = IPSet([ip])
    return ip

class Rules(object):
    def __init__(self, filename):
        self.rules = pickle.load(open(filename))

    def assertDenies(self, src, dst, app):
        """Assert that no flow matching [src -> dst : app] is allowed"""
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("assertDenies(%r, %r, %r)" % (src, dst, app))
        failures = 0
        for rule in self.rules:
            # TODO: it'd be useful to have rules by app here
            if rule.app != app:
                continue
            src_matches = (rule.src & src)
            if not src_matches:
                continue
            dst_matches = (rule.dst & dst)
            if not dst_matches:
                continue
            log.error("policy %s permits %s traffic from %s to %s" % (rule.name, app, src_matches, dst_matches))
            failures += 1
        ok_(failures == 0, "%d matching rules" % failures)

    def assertPermits(self, src, dst, app):
        """Assert that all flows matching [src -> dst : app] are allowed"""
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("assertPermits(%r, %r, %r)" % (src, dst, app))
        remaining = IPPairs((src, dst))
        for rule in self.rules:
            # TODO: useful to have rules by app here
            if rule.app != app:
                continue
            if (rule.src & src) and (rule.dst & dst):
                log.info("matched policy %s from %s to %s" % (rule.name, rule.src, rule.dst))
                remaining = remaining - IPPairs((rule.src, rule.dst))
        if remaining:
            flows = ",\n".join("%s -> %s" % p for p in remaining)
            raise AssertionError("no rule found for flows, app %s\n%s" % (app, flows))

    def sourcesFor(self, dst, app, ignore_sources=None):
        """Return an IPSet with all sources for traffic to any IP in dst on
        application app, ignoring flows from ignore_sources"""
        # TODO: useful to have rules by app here, too!
        log.info("sourcesFor(%r, %r, ignore_sources=%r)" % (dst, app, ignore_sources))
        rv = IPSet()
        for rule in self.rules:
            if rule.app != app:
                continue
            if rule.dst & dst:
                src = rule.src
                if ignore_sources:
                    src = src - ignore_sources
                if src:
                    log.info("matched policy %s from %s to %s" % (rule.name, src, rule.dst & dst))
                    rv = rv + src
        return rv

    def allApps(self, src, dst, debug=False):
        """Return a set of applications with access form src to dst.  Pass
        debug=True to log the full list of matching flows"""
        log.info("appsTo(%r, %r)" % (src, dst))
        rv = set()
        for rule in self.rules:
            if not debug and rule.app in rv:
                continue
            src_matches = (rule.src & src)
            if not src_matches:
                continue
            dst_matches = (rule.dst & dst)
            if not dst_matches:
                continue
            log.info("matched policy %s from %s to %s: %s" % (rule.name, src_matches,
                                                              dst_matches, rule.app))
            rv.add(rule.app)
        return rv

    def appsOn(self, dst, ignore_sources=None, debug=False):
        """Return a set of applications with access to dst, ignoring flows from ignore_sources)
        application app, ignoring flows from ignore.  Pass debug=True to log the full list of
        matching flows."""
        log.info("appsOn(%r, ignore_sources=%r)" % (dst, ignore_sources))
        rv = set()
        for rule in self.rules:
            if not debug and rule.app in rv:
                continue
            if rule.dst & dst:
                src = rule.src
                if ignore_sources:
                    src = src - ignore_sources
                if src:
                    log.info("matched policy %s from %s to %s: %s" % (rule.name, src,
                                                                      rule.dst & dst, rule.app))
                    rv.add(rule.app)
        return rv

