#! /usr/bin/python

from IPy import IP, IPSet
import xml.etree.ElementTree as ET

# parse the output of show security policies | display xml | save dustin.xml

class Policy(object):
    def __init__(self, from_zone, to_zone, policy_information_elt):
        self.from_zone = from_zone
        self.to_zone = to_zone
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
    """Parse out the correspondance between IP space and interfaces, on the
    assumption that reverse and forward paths match."""

    def __init__(self, rt_elt):
        self._parse(rt_elt)

    def __str__(self):
        return "%s via %s" % (self.destination, self.interface)

    def _parse(self, rt_elt):
        self.destination = IP(rt_elt.find('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt-destination').text)
        self.interface = None
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
        self._parse(zones_security_elt)

    def __str__(self):
        return "%s on %s" % (self.name, self.interfaces)

    def _parse(self, zones_security_elt):
        self.name = zones_security_elt.find('{http://xml.juniper.net/junos/12.1X44/junos-zones}zones-security-zonename').text
        self.interfaces = []
        for elt in zones_security_elt.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-zones}zones-security-interface-name'):
            self.interfaces.append(elt.text)


class Firewall(object):
    def __init__(self, fw, show_security_policies_elt, show_route_elt, show_security_zones_elt):
        self.fw = fw
        self.policies = []
        self.routes = []
        self.zones = []
        self._parse_policies(show_security_policies_elt)
        self._parse_routes(show_route_elt)
        self._parse_zones(show_security_zones_elt)

    def _parse_policies(self, show_security_policies_elt):
        for elt in show_security_policies_elt.findall('.//security-context'):
            from_zone = elt.find('./context-information/source-zone-name').text
            to_zone = elt.find('./context-information/destination-zone-name').text
            for pol_elt in elt.findall('./policies/policy-information'):
                policy = Policy(from_zone, to_zone, pol_elt)
                self.policies.append(policy)

    def _parse_routes(self, show_route_elt):
        sre = show_route_elt
        # thanks for the namespaces, Juniper.
        for table in sre.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}route-table'):
            if table.findtext('{http://xml.juniper.net/junos/12.1X44/junos-routing}table-name') == 'inet.0':
                for rt_elt in table.findall('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt'):
                    self.routes.append(Route(rt_elt))
                return

    def _parse_zones(self, show_security_zones_elt):
        ssze = show_security_zones_elt
        for zs in ssze.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-zones}zones-security'):
            self.zones.append(Zone(zs))

def process(fw):
    # figure out the IPSet routed via each interface
    routes = fw.routes[:]
    routes.sort(key=lambda r: -r.destination.prefixlen())
    matched = IPSet()
    interface_ips = {}
    for r in routes:
        if not r.interface:
            continue
        destset = IPSet([r.destination])
        interface_ips[r.interface] = interface_ips.get(r.interface, IPSet()) + (destset - matched)
        matched = matched + destset

    # figure out the IPSet of IPs for each security zone
    zone_nets = {}
    for zone in fw.zones:
        net = IPSet()
        for itfc in zone.interfaces:
            net += interface_ips[itfc]
        zone_nets[zone.name] = net
    import pprint
    pprint.pprint(zone_nets)

    # now, sort rules by their (zone-limited) source and destination nets
    # TODO: need address books

def main():
    ET.register_namespace('jr', 'http://xml.juniper.net/junos/12.1X44/junos-routing')
    firewall = Firewall("fw1.releng.scl3",
        show_security_policies_elt=ET.parse('fw1_releng_scl3_show_security_policies.xml').getroot(),
        show_route_elt=ET.parse('fw1_releng_scl3_show_route.xml').getroot(),
        show_security_zones_elt=ET.parse('fw1_releng_scl3_show_security_zones.xml').getroot())

    process(firewall)

main()
