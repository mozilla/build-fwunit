#! /usr/bin/python

import copy
import itertools
from IPy import IP, IPSet
from collections import namedtuple
import xml.etree.ElementTree as ET

# monkey-patch IPSet.isdisjoint, since the default is broken
# https://github.com/haypo/python-ipy/issues/21
def isdisjoint(self, other):
    left = iter(self.prefixes)
    right = iter(other.prefixes)
    try:
        l = left.next()
        r = right.next()
        while True:
            if l in r or r in l:
                return False
            if l < r:
                l = left.next()
            else:
                r = right.next()
    except StopIteration:
        return True
IPSet.isdisjoint = isdisjoint

assert IPSet([IP('0.0.0.0/1')]).isdisjoint(IPSet([IP('128.0.0.0/1')]))
assert not IPSet([IP('0.0.0.0/1')]).isdisjoint(IPSet([IP('0.0.0.0/2')]))
assert not IPSet([IP('0.0.0.0/2')]).isdisjoint(IPSet([IP('0.0.0.0/1')]))
assert not IPSet([IP('0.0.0.0/2')]).isdisjoint(IPSet([IP('0.1.2.3')]))
assert not IPSet([IP('0.1.2.3')]).isdisjoint(IPSet([IP('0.0.0.0/2')]))
assert IPSet([IP('1.1.1.1'), IP('1.1.1.3')]).isdisjoint(IPSet([IP('1.1.1.2'), IP('1.1.1.4')]))
assert not IPSet([IP('1.1.1.1'), IP('1.1.1.3'), IP('1.1.2.0/24')]).isdisjoint(IPSet([IP('1.1.2.2'), IP('1.1.1.4')]))

# monkey-patch IPSet.__and__, since the default is broken
def __and__(self, other):
    left = iter(self.prefixes)
    right = iter(other.prefixes)
    result = []
    try:
        l = left.next()
        r = right.next()
        while True:
            if l in r:
                result.append(l)
                l = left.next()
                continue
            elif r in l:
                result.append(r)
                r = right.next()
                continue
            if l < r:
                l = left.next()
            else:
                r = right.next()
    except StopIteration:
        return IPSet(result)
IPSet.__and__ = __and__

# A rule is a simple derivative of a policy:
# - always 'permit'
# - only one app
# - ipsets for source and destinations
# - no reference to zones
Rule = namedtuple('Rule', ['src', 'dst', 'app', 'name'])


class IPPairs(object):
    """
    Reasonably compact representation of a set of source-destination pairs,
    with the ability to do some basic arithmetic.
    """

    def __init__(self, *pairs):
        self._pairs = sorted(pairs)

    def __iter__(self):
        return self._pairs.__iter__()

    def __eq__(self, other):
        # this isn't quite right, as there are several ways to describe
        # a particular set of IP pairs as sets of IPSets
        return self._pairs == other._pairs

    def __repr__(self):
        return 'IPPairs(*[\n%s\n])' % ('\n'.join("  " + `p` for p in self._pairs))

    def __sub__(self, other):
        new_pairs = []
        empty = lambda pair: len(pair[0]) == 0 or len(pair[1]) == 0
        for sa, da in self._pairs:
            for sb, db in other._pairs:
                # eliminate non-overlap
                if sa.isdisjoint(sb) or da.isdisjoint(db):
                    new_pairs.append((sa, da))
                    continue
                for pair in (sa&sb, da-db), (sa-sb, da-db), (sa-sb, da&db):
                    if not empty(pair):
                        new_pairs.append(pair)
        return IPPairs(*new_pairs)


    def __nonzero__(self):
        return len(self._pairs) != 0

    @classmethod
    def test(cls):
        any = IPSet([IP('0.0.0.0/0')])
        ten = IPSet([IP('10.0.0.0/8')])
        ten26 = IPSet([IP('10.26.0.0/16')])
        ten33 = IPSet([IP('10.33.0.0/16')])
        print IPPairs((any,any)) - IPPairs((any, ten))
        print IPPairs((any,any)) - IPPairs((any, ten)) - IPPairs((any, ten26))
        print IPPairs((any,any)) - IPPairs((any, ten)) - IPPairs((ten26, any))
        print IPPairs((any, ten26+ten33)) - IPPairs((any, ten))

class Policy(object):
    def __init__(self, from_zone, to_zone, policy_information_elt):
        #: policy name
        self.name = None

        #: source zone name for this policy
        self.from_zone = from_zone

        #: destination zone name for this policy
        self.to_zone = to_zone

        #: boolean, true if the policy is enabled
        self.enabled = None

        #: policy sequence number
        self.sequence = None

        #: source addresses (by name) for the policy
        self.source_addresses = []

        #: destination addresses (by name) for the policy
        self.destination_addresses = []

        #: applications (name) for the policy
        self.applications = []

        #: 'accept' or 'deny'
        self.action = None

        self._parse(policy_information_elt)

    def __str__(self):
        return ("%(action)s %(from_zone)s:%(source_addresses)r -> "
               "%(to_zone)s:%(destination_addresses)r : %(applications)s") % self.__dict__

    def _parse(self, policy_information_elt):
        pie = policy_information_elt
        self.name = pie.find('./policy-name').text
        self.enabled = pie.find('./policy-state').text == 'enabled'
        self.sequence = int(pie.find('./policy-sequence-number').text)
        self.source_addresses = [self._parse_address(e) for e in pie.findall('./source-addresses/*')]
        self.destination_addresses = [self._parse_address(e) for e in pie.findall('./destination-addresses/*')]
        self.applications = [self._parse_application(e) for e in pie.findall('./applications/application')]
        self.action = pie.find('./policy-action/action-type').text

    def _parse_address(self, elt):
        addrname = elt.find('./address-name')
        return addrname.text

    def _parse_application(self, elt):
        appname = elt.find('./application-name')
        return appname.text


class Route(object):
    """A route from the firewall's routing table"""

    def __init__(self, rt_elt):
        #: IPSet based on the route destination
        self.destination = None

        #: interface to which traffic is forwarded (via or local)
        self.interface = None

        self._parse(rt_elt)

    def __str__(self):
        return "%s via %s" % (self.destination, self.interface)

    def _parse(self, rt_elt):
        self.destination = IP(rt_elt.find('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt-destination').text)
        for entry in rt_elt.findall('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt-entry'):
            if entry.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}current-active'):
                vias = entry.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}via')
                if vias:
                    self.interface = vias[0].text
                locals = entry.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}nh-local-interface')
                if locals:
                    self.interface = locals[0].text


class Zone(object):
    """Parse out zone names and the corresponding interfaces"""

    def __init__(self, zones_security_elt):
        #: list of interface names
        self.interfaces = []

        #: name -> ipset, based on the zone's address book
        self.addresses = {'any': IPSet([IP('0.0.0.0/0')])}

        self._parse(zones_security_elt)

    def __str__(self):
        return "%s on %s" % (self.name, self.interfaces)

    def _parse(self, security_zone_elt):
        sze = security_zone_elt
        self.name = sze.find('name').text

        # interfaces
        for itfc in sze.findall('.//interfaces/name'):
            self.interfaces.append(itfc.text)

        # address book
        for addr in sze.find('address-book'):
            name = addr.findtext('name')
            if addr.tag == 'address':
                ip = IPSet([IP(addr.findtext('ip-prefix'))])
            else:  # note: assumes address-sets follow addresses
                ip = IPSet()
                for setaddr in addr.findall('address'):
                    setname = setaddr.findtext('name')
                    ip += self.addresses[setname]
            self.addresses[name] = ip


class Firewall(object):
    def __init__(self, fw, show_security_policies_elt,
                 show_route_elt, show_configuration_security_zones_elt):
        #: firewall name
        self.fw = fw

        #: zone name -> IPSet
        self.zone_nets = {}

        policies = self._parse_policies(show_security_policies_elt)
        routes = self._parse_routes(show_route_elt)
        zones = self._parse_zones(show_configuration_security_zones_elt)

        self._process(policies, routes, zones)

    def _parse_policies(self, show_security_policies_elt):
        policies = []
        for elt in show_security_policies_elt.findall('.//security-context'):
            from_zone = elt.find('./context-information/source-zone-name').text
            to_zone = elt.find('./context-information/destination-zone-name').text
            for pol_elt in elt.findall('./policies/policy-information'):
                policy = Policy(from_zone, to_zone, pol_elt)
                policies.append(policy)
        return policies

    def _parse_routes(self, show_route_elt):
        sre = show_route_elt
        routes = []
        # thanks for the namespaces, Juniper.
        for table in sre.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}route-table'):
            if table.findtext('{http://xml.juniper.net/junos/12.1X44/junos-routing}table-name') == 'inet.0':
                for rt_elt in table.findall('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt'):
                    routes.append(Route(rt_elt))
                return routes
        return []

    def _parse_zones(self, show_configuration_security_zones_elt):
        scsz = show_configuration_security_zones_elt
        zones = []
        for sz in scsz.findall('.//security-zone'):
            zones.append(Zone(sz))
        return zones

    def _process(self, policies, routes, zones):
        # process the parsed data into a queryable format

        # figure out the IPSet routed via each interface, by starting with the most
        # specific and only considering IP space not already allocated to an
        # interface.  This has the effect of leaving a "swiss cheese" default route
        # containing all IPs that aren't routed by a more-specific route.
        routes = routes[:]
        routes.sort(key=lambda r: -r.destination.prefixlen())
        matched = IPSet()
        interface_ips = {}
        for r in routes:
            if not r.interface:
                continue
            destset = IPSet([r.destination])
            interface_ips[r.interface] = interface_ips.get(r.interface, IPSet()) + (destset - matched)
            matched = matched + destset

        # figure out the IPSet of IPs for each security zone.  This makes the
        # assumption (just like RFP) that each IP will communicate on exactly one
        # firewall interface.  Each interface is in exactly one zone, so this means
        # that each IP is in exactly one zone.
        zone_nets = {}
        for zone in zones:
            net = IPSet()
            for itfc in zone.interfaces:
                net += interface_ips[itfc]
            zone_nets[zone.name] = net
        self.zone_nets = zone_nets

        # organize policies by to/from zone pair
        policies_by_zone_pair = {}
        for pol in policies:
            policies_by_zone_pair.setdefault((pol.from_zone, pol.to_zone), []).append(pol)

        # compute actual address sets per policy
        src_per_policy = {}
        dst_per_policy = {}
        zones_by_name = dict((z.name, z) for z in zones)
        for (from_zone, to_zone), zpolicies in policies_by_zone_pair.iteritems():
            from_addrbook = zones_by_name[from_zone].addresses
            to_addrbook = zones_by_name[to_zone].addresses
            for pol in zpolicies:
                src_per_policy[pol] = sum((from_addrbook[a] for a in pol.source_addresses), IPSet())
                dst_per_policy[pol] = sum((to_addrbook[a] for a in pol.destination_addresses), IPSet())

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
            print "from", from_zone, "to", to_zone
            zpolicies.sort(key=lambda p: p.sequence)
            apps = set(itertools.chain(*[p.applications for p in zpolicies]))
            if 'any' in apps:
                apps = all_apps
            for app in apps:
                # for each app, countdown the IP pairs that have not matched a
                # rule yet, starting with the zones' IP spaces.  This simulates sequential
                # processing of the policies.
                remaining_pairs = IPPairs((zone_nets[from_zone], zone_nets[to_zone]))
                rules = rules_by_app.setdefault(app, [])
                for pol in zpolicies:
                    if app not in pol.applications and 'any' not in pol.applications:
                        continue
                    src = src_per_policy[pol]
                    dst = dst_per_policy[pol]
                    # if the policy is a "permit", add rules for each src/destination pair
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
        # destination by combining them.  TODO: I suspect this needs to be
        # repeated until it's stable?
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
                        rule = Rule(last.src+rule.src, 
                                    last.dst+rule.dst,
                                    app,
                                    last.name)
                        rv[-1] = rule
                    else:
                        rv.append(rule)
                    last = rule
                rules = rv
            rules_by_app[app] = rules
            
        import pprint
        pprint.pprint(rules_by_app['tomcat'])
        self.rules_by_app = rules_by_app


def main():
    ET.register_namespace('jr', 'http://xml.juniper.net/junos/12.1X44/junos-routing')
    firewall = Firewall("fw1.releng.scl3",
        show_security_policies_elt=ET.parse('fw1_releng_scl3_show_security_policies.xml').getroot(),
        show_route_elt=ET.parse('fw1_releng_scl3_show_route.xml').getroot(),
        show_configuration_security_zones_elt=ET.parse('fw1_releng_scl3_show_configuration_security_zones.xml').getroot())

main()
