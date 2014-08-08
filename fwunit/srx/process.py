# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import itertools
from fwunit.ip import IPSet, IPPairs
from fwunit.types import Rule
from .parse import Policy
from logging import getLogger

log = getLogger(__name__)

def policies_to_rules(firewall):
    """Process the data in a parse.Firewall instance into a list of non-overlapping
    Rule instances, suitable for queries"""
    interface_ips = process_interface_ips(firewall.routes)
    zone_nets = process_zone_nets(firewall.zones, interface_ips)
    policies_by_zone_pair = process_policies_by_zone_pair(firewall.policies)
    attached_networks = process_attached_networks(firewall.routes)
    policies_by_zone_pair = process_attached_network_policies(
        policies_by_zone_pair, zone_nets, attached_networks)
    src_per_policy, dst_per_policy = process_address_sets_per_policy(
        firewall.zones, policies_by_zone_pair)
    return process_rules(firewall.policies, zone_nets, policies_by_zone_pair, src_per_policy,
                         dst_per_policy)


def process_interface_ips(routes):
    # figure out the IPSet routed via each interface, by starting with the most
    # specific and only considering IP space not already allocated to an
    # interface.  This has the effect of leaving a "swiss cheese" default route
    # containing all IPs that aren't routed by a more-specific route.
    log.info("calculating interface IP ranges")
    routes = routes[:]
    routes.sort(key=lambda r: -r.destination.prefixlen())
    matched = IPSet()
    interface_ips = {}
    for r in routes:
        if not r.interface:
            continue
        destset = IPSet([r.destination])
        interface_ips[r.interface] = interface_ips.get(
            r.interface, IPSet()) + (destset - matched)
        matched = matched + destset
    return interface_ips


def process_attached_networks(routes):
    # return a list of networks to which this firewall is directly connected,
    # so there is no "next hop".
    log.info("calculating attached networks")
    networks = [IPSet([r.destination]) for r in routes if r.is_local]
    return networks


def process_zone_nets(zones, interface_ips):
    # figure out the IPSet of IPs for each security zone.  This makes the
    # assumption (just like RFP) that each IP will communicate on exactly one
    # firewall interface.  Each interface is in exactly one zone, so this means
    # that each IP is in exactly one zone.
    log.info("calculating zone IP ranges")
    zone_nets = {}
    for zone in zones:
        net = IPSet()
        for itfc in zone.interfaces:
            net += interface_ips[itfc]
        zone_nets[zone.name] = net
    return zone_nets


def process_policies_by_zone_pair(policies):
    log.info("tabulating policies by zone")
    policies_by_zone_pair = {}
    for pol in policies:
        policies_by_zone_pair.setdefault(
            (pol.from_zone, pol.to_zone), []).append(pol)
    return policies_by_zone_pair


def process_attached_network_policies(policies_by_zone_pair, zone_nets, attached_networks):
    # include a full permit policy for traffic within each attached network,
    # since such traffic will flow within that network and not through the
    # firewall.
    for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
        if from_zone != to_zone:
            continue
        zone_net = zone_nets[from_zone]
        for att in attached_networks:
            if att & zone_net:
                pfx = str(att.prefixes[0])
                pol = Policy()
                pol.name = "local-%s" % pfx
                pol.from_zone = from_zone
                pol.to_zone = to_zone
                pol.enabled = True
                pol.sequence = -1
                # these lists ordinarily contain address names, but these are
                # IPSets.  This is handled in process_adddress_sets_per_policy.
                pol.source_addresses = [att]
                pol.destination_addresses = [att]
                pol.applications = ['any']
                pol.action = 'permit'
                zpolicies.insert(0, pol)
    # this has been modified in place:
    return policies_by_zone_pair


def process_address_sets_per_policy(zones, policies_by_zone_pair):
    log.info("computing address sets per policy")
    src_per_policy = {}
    dst_per_policy = {}
    zones_by_name = dict((z.name, z) for z in zones)
    for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
        from_addrbook = zones_by_name[from_zone].addresses
        get_from = lambda a: a if isinstance(a, IPSet) else from_addrbook[a]
        to_addrbook = zones_by_name[to_zone].addresses
        get_to = lambda a: a if isinstance(a, IPSet) else to_addrbook[a]
        for pol in zpolicies:
            src_per_policy[pol] = sum(
                (get_from(a) for a in pol.source_addresses), IPSet())
            dst_per_policy[pol] = sum(
                (get_to(a) for a in pol.destination_addresses), IPSet())
    return src_per_policy, dst_per_policy


def process_rules(policies, zone_nets, policies_by_zone_pair, src_per_policy,
                  dst_per_policy):
    log.info("processing rules by application")
    # turn policies into a list of Rules (permit only), limited by zone,
    # that do not overlap.  The tricky bit here is processing policies in
    # order and accounting for denies.  We do this once for each
    # (from_zone, to_zone, app) tuple.  The other tricky bit is handling
    # the application "any", which we treat as including all applications
    # used anywhere.
    rules_by_app = {}
    all_apps = set(itertools.chain(*[p.applications for p in policies]))
    if 'any' in all_apps:
        all_apps.remove('any')
    for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
        log.debug(" from-zone %s to-zone %s (%d policies)", from_zone, to_zone, len(zpolicies))
        rule_count = 0
        zpolicies.sort(key=lambda p: p.sequence)
        apps = set(itertools.chain(*[p.applications for p in zpolicies]))
        if 'any' in apps:
            apps = all_apps
        for app in apps:
            # for each app, count down the IP pairs that have not matched a
            # rule yet, starting with the zones' IP spaces.  This simulates sequential
            # processing of the policies.
            remaining_pairs = IPPairs(
                (zone_nets[from_zone], zone_nets[to_zone]))
            rules = rules_by_app.setdefault(app, [])
            for pol in zpolicies:
                if app not in pol.applications and 'any' not in pol.applications:
                    continue
                src = src_per_policy[pol]
                dst = dst_per_policy[pol]
                # if the policy is a "permit", add rules for each
                # src/destination pair
                if pol.action == 'permit':
                    for s, d in remaining_pairs:
                        s = s & src
                        d = d & dst
                        if len(s) and len(d):
                            rules.append(Rule(s, d, app, pol.name))
                            rule_count += 1
                # regardless, consider this src/dst pair matched
                remaining_pairs = remaining_pairs - IPPairs((src, dst))
                # if we've matched everything, we're done
                if not remaining_pairs:
                    break
        log.debug(" from-zone %s to-zone %s => %d rules", from_zone, to_zone, rule_count)

    # now, simplify rules with the same application and the same source or
    # destination by combining them.
    log.info("combining rules")
    pass_num = 1
    while True:
        log.debug(" pass %d", pass_num)
        pass_num += 1
        combined = 0
        for app, rules in rules_by_app.iteritems():
            for combine_by in 0, 1:  # src, dst
                # sort by prefix, so that identical IPSets sort together
                rules.sort(key=lambda r: (r[combine_by].prefixes, r.name))
                rv = []
                last = None
                for rule in rules:
                    if last and last[combine_by] == rule[combine_by] and last.name == rule.name:
                        rule = Rule(last.src + rule.src,
                                    last.dst + rule.dst,
                                    app,
                                    last.name)
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
        log.debug("  eliminated %d rules" % combined)

    # convert from by_app to just a list of rules (which include the app)
    return list(itertools.chain(*rules_by_app.itervalues()))
