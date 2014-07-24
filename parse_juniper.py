#! /usr/bin/python

import cPickle as Pickle
import sys
import argparse
import itertools
from fwunit.ip import IPSet, IPPairs
from fwunit.types import Rule
from fwunit.parse import Firewall


def process(firewall):
    # process the parsed data into a queryable format
    interface_ips = process_interface_ips(firewall.routes)
    zone_nets = process_zone_nets(firewall.zones, interface_ips)
    policies_by_zone_pair = process_policies_by_zone_pair(firewall.policies)
    src_per_policy, dst_per_policy = process_address_sets_per_policy(
        firewall.zones, policies_by_zone_pair)
    return process_rules(firewall.policies, zone_nets, policies_by_zone_pair, src_per_policy, dst_per_policy)


def process_interface_ips(routes):
    # figure out the IPSet routed via each interface, by starting with the most
    # specific and only considering IP space not already allocated to an
    # interface.  This has the effect of leaving a "swiss cheese" default route
    # containing all IPs that aren't routed by a more-specific route.
    print "calculating interface IP ranges"
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


def process_zone_nets(zones, interface_ips):
    # figure out the IPSet of IPs for each security zone.  This makes the
    # assumption (just like RFP) that each IP will communicate on exactly one
    # firewall interface.  Each interface is in exactly one zone, so this means
    # that each IP is in exactly one zone.
    print "calculating zone IP ranges"
    zone_nets = {}
    for zone in zones:
        net = IPSet()
        for itfc in zone.interfaces:
            net += interface_ips[itfc]
        zone_nets[zone.name] = net
    return zone_nets


def process_policies_by_zone_pair(policies):
    print "tabulating policies by zone"
    policies_by_zone_pair = {}
    for pol in policies:
        policies_by_zone_pair.setdefault(
            (pol.from_zone, pol.to_zone), []).append(pol)
    return policies_by_zone_pair


def process_address_sets_per_policy(zones, policies_by_zone_pair):
    print "computing address sets per policy"
    src_per_policy = {}
    dst_per_policy = {}
    zones_by_name = dict((z.name, z) for z in zones)
    for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
        from_addrbook = zones_by_name[from_zone].addresses
        to_addrbook = zones_by_name[to_zone].addresses
        for pol in zpolicies:
            src_per_policy[pol] = sum(
                (from_addrbook[a] for a in pol.source_addresses), IPSet())
            dst_per_policy[pol] = sum(
                (to_addrbook[a] for a in pol.destination_addresses), IPSet())
    return src_per_policy, dst_per_policy


def process_rules(policies, zone_nets, policies_by_zone_pair, src_per_policy, dst_per_policy):
    print "processing rules by application"
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
        # XXX temporary
        if to_zone != 'srv':
            continue
        print ".. from", from_zone, "to", to_zone
        zpolicies.sort(key=lambda p: p.sequence)
        apps = set(itertools.chain(*[p.applications for p in zpolicies]))
        if 'any' in apps:
            apps = all_apps
        for app in apps:
            # for each app, countdown the IP pairs that have not matched a
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
                # regardless, consider this src/dst pair matched
                remaining_pairs = remaining_pairs - IPPairs((src, dst))
                # if we've matched everything, we're done
                if not remaining_pairs:
                    break

    # now, simplify rules with the same application and the same source or
    # destination by combining them.
    print "combining rules"
    pass_num = 1
    while True:
        print ".. pass", pass_num
        pass_num += 1
        combined = False
        for app, rules in rules_by_app.iteritems():
            # XXX temporary
            if app != 'tomcat':
                continue
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
                        combined = True
                    else:
                        rv.append(rule)
                    last = rule
                rules = rv
            rules_by_app[app] = rules

        # if nothing was combined on this iteration, we're done
        if not combined:
            break

    # convert from by_app to just a list of rules (which include the app)
    return list(itertools.chain(*rules_by_app.itervalues()))


def main():
    epilog = """
        Provide the following:
            --security-policies-xml: output of 'show security policies | display xml'
            --route-xml: output of 'show route | display xml'
            --configuration-security-zones-xml: output of 'show configuration security zones | display xml'
        The output will be written to --output, defaulting to 'rules.pkl'
    """
    parser = argparse.ArgumentParser(
        description='Ingest output from a Juniper firewall and create a datafile containing the results.', epilog=epilog)
    parser.add_argument(
        '--security-policies-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--route-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--configuration-security-zones-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--output', dest='output_file', type=str, default='rules.pkl')

    args = parser.parse_args(sys.argv[1:])

    firewall = Firewall(
        security_policies_xml=args.security_policies_xml,
        route_xml=args.route_xml,
        configuration_security_zones_xml=args.configuration_security_zones_xml)
    rules = process(firewall)
    Pickle.dump(rules, open(args.output_file, "w"))

if __name__ == "__main__":
    main()
