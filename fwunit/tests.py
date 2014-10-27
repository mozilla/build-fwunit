# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import json
import yaml
import os
import itertools
from fwunit.ip import IP, IPSet, IPPairs
from nose.tools import ok_
from fwunit import types
from blessings import Terminal

log = logging.getLogger(__name__)
terminal = Terminal()

def _ipset(ip):
    if isinstance(ip, basestring):
        ip = IP(ip)
    if isinstance(ip, IP):
        ip = IPSet([ip])
    return ip

class Rules(object):
    def __init__(self, source):
        if not os.path.exists('fwunit.yaml'):
            raise RuntimeError('Tests must be run from the directory containing `fwunit.yaml`')
        cfg = yaml.load(open('fwunit.yaml'))
        src_cfg = cfg[source]
        self.rules = types.from_jsonable(json.load(open(src_cfg['output']))['rules'])

    def _rules_for_app(self, app):
        # get the rules for the given app, or if no such app is known, for @@other
        try:
            return self.rules[app]
        except KeyError:
            return self.rules.get('@@other', [])

    def assertDenies(self, src, dst, app):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("assertDenies(%r, %r, %r)" % (src, dst, app))
        failures = 0
        for rule in self._rules_for_app(app):
            src_matches = (rule.src & src)
            if not src_matches:
                continue
            dst_matches = (rule.dst & dst)
            if not dst_matches:
                continue
            log.error("policy {t.cyan}{name}{t.normal} permits {t.bold_cyan}{app}{t.normal} "
                      "traffic\n{t.yellow}{src}{t.normal} -> {t.magenta}{dst}{t.normal}".format(
                t=terminal,
                name=rule.name,
                app=app,
                src=src_matches,
                dst=dst_matches)
                )
            failures += 1
        ok_(failures == 0, "%d matching rules" % failures)

    def assertPermits(self, src, dst, app):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("assertPermits(%r, %r, %r)" % (src, dst, app))
        remaining = IPPairs((src, dst))
        for rule in self._rules_for_app(app):
            if (rule.src & src) and (rule.dst & dst):
                log.info("matched policy {t.cyan}{name}{t.normal}\n{t.yellow}{src}{t.normal} "
                         "-> {t.magenta}{dst}{t.normal}".format(
                    t=terminal, name=rule.name, src=rule.src, dst=rule.dst))
                remaining = remaining - IPPairs((rule.src, rule.dst))
        if remaining:
            flows = ",\n".join("{t.yellow}{src}{t.normal} -> {t.magenta}{dst}{t.normal}".format(
                                t=terminal, src=p[0], dst=p[1]) for p in remaining)
            raise AssertionError("No rule found for flows, app {t.bold_cyan}{app}{t.normal}\n{flows}"
                                 .format(t=terminal, app=app, flows=flows))

    def sourcesFor(self, dst, app, ignore_sources=None):
        dst = _ipset(dst)
        log.info("sourcesFor(%r, %r, ignore_sources=%r)" % (dst, app, ignore_sources))
        rv = IPSet()
        for rule in self._rules_for_app(app):
            if rule.dst & dst:
                src = rule.src
                if ignore_sources:
                    src = src - ignore_sources
                if src:
                    log.info("matched policy {t.cyan}{name}{t.normal}\n{t.yellow}{src}{t.normal} "
                             "-> {t.magenta}{dst}{t.normal}".format(
                                t=terminal, name=rule.name, src=src, dst=rule.dst & dst))
                    rv = rv + src
        return rv

    def allApps(self, src, dst, debug=False):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("appsTo(%r, %r)" % (src, dst))
        rv = set()
        for rule in itertools.chain(*self.rules.itervalues()):
            if not debug and rule.app in rv:
                continue
            src_matches = (rule.src & src)
            if not src_matches:
                continue
            dst_matches = (rule.dst & dst)
            if not dst_matches:
                continue
            log.info("matched policy {t.cyan}{name}{t.normal} app {t.bold_cyan}{app}{t.normal}\n"
                     "{t.yellow}{src}{t.normal} -> {t.magenta}{dst}{t.normal}".format(
                        t=terminal, name=rule.name, src=src_matches, dst=dst_matches, app=rule.app))
            rv.add(rule.app)
        if '@@other' in rv:
            rv = set(['any'])
        return rv

    def assertAllApps(self, src, dst, apps, debug=False):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("appsOn(%r, %r, %r)" % (src, dst, apps))
        found_apps = set()
        for rule in itertools.chain(*self.rules.itervalues()):
            if not debug and rule.app in found_apps:
                continue
            if rule.dst & dst and rule.src & src:
                log.info("matched policy {t.cyan}{name}{t.normal} app {t.bold_cyan}{app}{t.normal}\n"
                            "{t.yellow}{src}{t.normal} -> {t.magenta}{dst}{t.normal}".format(
                            t=terminal, name=rule.name, src=src, dst=rule.dst & dst, app=rule.app))
                found_apps.add(rule.app)
        if found_apps != set(apps):
            raise AssertionError("got apps %r; expected %r" % (list(found_apps), list(apps)))
