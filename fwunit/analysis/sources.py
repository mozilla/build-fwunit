# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import itertools
import json
import os.path
import logging

from blessings import Terminal
from fwunit import types
from fwunit.ip import IP, IPSet, IPPairs

log = logging.getLogger(__name__)
terminal = Terminal()

def _ipset(ip):
    if isinstance(ip, basestring):
        ip = IP(ip)
    if isinstance(ip, IP):
        ip = IPSet([ip])
    return ip

class Source(object):
    def __init__(self, filename):
        self.rules = types.from_jsonable(json.load(open(filename))['rules'])

    def rulesForApp(self, app):
        try:
            return self.rules[app]
        except KeyError:
            return self.rules.get('@@other', [])

    def rulesDeny(self, src, dst, apps):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("rulesDeny(%r, %r, %r)" % (src, dst, apps))
        failures = 0
        apps = apps if not isinstance(apps, basestring) else [apps]
        for app in apps:
            log.info("checking application %r" % app)
            for rule in self.rulesForApp(app):
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
        return failures == 0

    def rulesPermit(self, src, dst, apps):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("rulesPermit(%r, %r, %r)" % (src, dst, apps))
        remaining = IPPairs((src, dst))
        apps = apps if not isinstance(apps, basestring) else [apps]
        for app in apps:
            log.info("checking application %r" % app)
            for rule in self.rulesForApp(app):
                if (rule.src & src) and (rule.dst & dst):
                    log.info("matched policy {t.cyan}{name}{t.normal}\n{t.yellow}{src}{t.normal} "
                            "-> {t.magenta}{dst}{t.normal}".format(
                        t=terminal, name=rule.name, src=rule.src, dst=rule.dst))
                    remaining = remaining - IPPairs((rule.src, rule.dst))
        if remaining:
            flows = ",\n".join("{t.yellow}{src}{t.normal} -> {t.magenta}{dst}{t.normal}".format(
                                t=terminal, src=p[0], dst=p[1]) for p in remaining)
            log.error("No rule found for flows, app {t.bold_cyan}{app}{t.normal}\n{flows}"
                                 .format(t=terminal, app=app, flows=flows))
            return False
        return True

    def allApps(self, src, dst, debug=False):
        src = _ipset(src)
        dst = _ipset(dst)
        log.info("allApps(%r, %r)" % (src, dst))
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

    def sourcesFor(self, dst, app, ignore_sources=None):
        dst = _ipset(dst)
        log.info("sourcesFor(%r, %r, ignore_sources=%r)" % (dst, app, ignore_sources))
        rv = IPSet()
        for rule in self.rulesForApp(app):
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

_cache = {}


def load_source(cfg, source):
    """Load the named source.  Sources are cached, so multiple calls with the same name
    will not repeatedly re-load the data from disk.  The source can name a source from
    the configuration, or a filename."""
    if source not in _cache:
        if source in cfg:
            filename = cfg[source]['output']
        elif os.path.exists(source):
            filename = source
        else:
            raise KeyError("unknown source {}".format(source))
        _cache[source] = Source(filename)
    return _cache[source]


def _clear():
    # for tests only
    global _cache
    _cache = {}
