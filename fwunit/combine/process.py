# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import collections
from fwunit.ip import IP, IPSet
import logging
from fwunit.types import Rule
from fwunit.common import simplify_rules
from fwunit.common import combine_names

logger = logging.getLogger(__name__)

AddressSpace = collections.namedtuple(
    "AddressSpace", ['rules', 'ip_space', 'name'])


def combine(input_rules):
    # translate from config (YAML data) into actual IPSets
    address_spaces = []
    all_apps = set()
    for name, info in input_rules.iteritems():
        ip_space = IPSet([IP(s) for s in info['ip_space']])
        rules_by_app = {}
        for r in info['rules']:
            rules_by_app.setdefault(r.app, []).append(r)
        all_apps = all_apps | set(rules_by_app)
        address_spaces.append(
            AddressSpace(rules=rules_by_app, ip_space=ip_space,
                         name=name))

    # add an "unmanaged" address space allowing all flows into or out of managed ip
    # space, but not between unmanaged IPs (the latter restriction effectively
    # omits uninteresting flows)
    managed_space = IPSet([])
    for sp in address_spaces:
        managed_space += sp.ip_space
    unmanaged_space = IPSet([IP('0.0.0.0/0')]) - managed_space
    if unmanaged_space:
        rules = {
            app: [Rule(src=managed_space, dst=unmanaged_space,
                       app=app, name="unmanaged-{}".format(app)),
                  Rule(src=unmanaged_space, dst=managed_space,
                       app=app, name="unmanaged-{}".format(app))]
            for app in all_apps}
        address_spaces.append(
            AddressSpace(rules=rules, ip_space=unmanaged_space, name="unmanaged"))

    combined_rules = []
    for app in all_apps:
        logger.info("combining app %s", app)
        # The idea here is this: for each pair of address spaces, look at rules
        # between those address spaces, limited to those address spaces.  Only
        # write combined rules for flows for which both address spaces have a
        # rule.
        for local_sp in address_spaces:
            local_rules = local_sp.rules.get(app)
            if not local_rules:
                continue
            for remote_sp in address_spaces:
                remote_rules = remote_sp.rules.get(app)
                if not remote_rules:
                    continue
                logger.debug(" from %s to %s", local_sp.name, remote_sp.name)
                for lr in local_rules:
                    local_src = lr.src & local_sp.ip_space
                    if not local_src:
                        continue
                    local_dst = lr.dst & remote_sp.ip_space
                    if not local_dst:
                        continue
                    for rr in remote_rules:
                        combined_src = local_src & rr.src
                        if not combined_src:
                            continue
                        combined_dst = local_dst & rr.dst
                        if not combined_dst:
                            continue
                        combined_rules.append(Rule(
                            src=combined_src,
                            dst=combined_dst,
                            app=app,
                            name=combine_names(lr.name, rr.name)))

    rules = simplify_rules(combined_rules)
    return rules
