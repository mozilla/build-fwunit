# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
from fwunit.types import Rule
from fwunit.common import simplify_rules
from fwunit.common import combine_names

logger = logging.getLogger(__name__)

def combine(address_spaces, routes, sources):
    # get the set of all apps
    all_apps = set()
    for rules in sources.itervalues():
        all_apps = all_apps | set(rules)

    # for each address space, add any apps which aren't explicitly specified in that
    # address space, but *are* specified in the combined ruleset, as copies of that
    # address space's '@@other' app.  This ensures that each space has the same set
    # of apps.
    for rules in sources.itervalues():
        other = rules.get('@@other', [])
        missing_apps = all_apps - set(rules)
        for app in missing_apps:
            rules[app] = [Rule(src=r.src, dst=r.dst, app=app, name=r.name)
                          for r in other]

    combined_rules = {}
    for app in all_apps:
        logger.info("combining app %s", app)
        # The idea here is this: for each pair of address spaces, look at the
        # set of rules specified in the routes.  Only write combined rules for
        # flows for which are allowed by all rulesets.
        for local_sp_name, local_sp in address_spaces.iteritems():
            for remote_sp_name, remote_sp in address_spaces.iteritems():
                source_names = routes[local_sp_name, remote_sp_name]
                if not source_names:
                    continue
                logger.debug(" from %s to %s using %s",
                        local_sp_name, remote_sp_name, ', '.join(source_names))
                rulesets = [sources[n][app] for n in source_names]

                # if we only have one source, this is pretty easy:
                # just limit each rule to the relevant IP spaces; otherwise
                # we need to do a recursive intersection
                if len(rulesets) == 1:
                    new_rules = rules_from_to(rulesets[0], local_sp, remote_sp)
                else:
                    new_rules = intersect_rules(rulesets, local_sp, remote_sp)
                if new_rules:
                    combined_rules.setdefault(app, []).extend(new_rules)

    rules = simplify_rules(combined_rules)
    return rules

def rules_from_to(rules, local_sp, remote_sp):
    rv = []
    for r in rules:
        src = r.src & local_sp
        if not src:
            continue
        dst = r.dst & remote_sp
        if not dst:
            continue
        rv.append(Rule(src=src, dst=dst, app=r.app, name=r.name))
    return rv

def intersect_rules(rulesets, local_sp, remote_sp):
    # combine the rulesets into an accumulator seeded with the first
    # ruleset
    acc = rules_from_to(rulesets.pop(), local_sp, remote_sp)
    while rulesets:
        rs = rules_from_to(rulesets.pop(), local_sp, remote_sp)
        intersected = []
        for rl in acc:
            for rr in rs:
                src = rl.src & rr.src
                if not src:
                    continue
                dst = rl.dst & rr.dst
                if not dst:
                    continue
                intersected.append(Rule(
                    src=src, dst=dst, app=rl.app,
                    name=combine_names(rl.name, rr.name)))
        acc = intersected
    return acc
