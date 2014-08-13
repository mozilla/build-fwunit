# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import itertools
from .types import Rule

logger = logging.getLogger(__name__)


def combine_names(name1, name2):
    """Combine rule names, keeping all source names but removing duplicates"""
    names = set(name1.split('+')) | set(name2.split('+'))
    # as a special case, ignore 'unmanaged-*' names, as they add no useful information
    names = [n for n in names if not n.startswith('unmanaged-')]
    return '+'.join(sorted(names))


def simplify_rules(rules):
    """Simplify rules by combining rules with the same application and exactly
    the same source, or exactly the same destination -- repeatedly, until
    nothing changes."""
    logger.info("simplifying %d rules", len(rules))
    rules_by_app = {}
    for rule in rules:
        rules_by_app.setdefault(rule.app, []).append(rule)
    pass_num = 1
    while True:
        logger.debug(" pass %d", pass_num)
        pass_num += 1
        combined = 0
        for app, rules in rules_by_app.iteritems():
            for combine_by in 0, 1:  # src, dst
                # sort by prefix, so that identical IPSets sort together
                rules.sort(key=lambda r: (r[combine_by].prefixes, r.name))
                rv = []
                last = None
                for rule in rules:
                    if last and last[combine_by] == rule[combine_by]:
                        rule = Rule(last.src + rule.src,
                                    last.dst + rule.dst,
                                    app,
                                    combine_names(last.name, rule.name))
                        rv[-1] = rule
                        combined += 1
                    else:
                        rv.append(rule)
                    last = rule
                rules = rv
            rules_by_app[app] = rules

        # if nothing was combined on this iteration, we're done
        if not combined:
            break
        logger.debug("  eliminated %d rules", combined)

    rules = list(itertools.chain(*rules_by_app.values()))
    logger.debug(" result: %d rules", len(rules))
    return rules


class ApplicationMap(object):
    """Handle the common 'application-map' configuration."""

    def __init__(self, config):
        self._map = config.get('application-map', {})
        # check for duplicate values
        seen = set()
        for v in self._map.itervalues():
            if v in seen:
                raise RuntimeError("duplicate common application name {}".format(v))
            seen.add(v)

    def __getitem__(self, app):
        return self._map.get(app, app)

    def keys(self):
        return self._map.keys()

    def values(self):
        return self._map.values()
