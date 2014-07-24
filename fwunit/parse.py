# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import xml.etree.ElementTree as ET
from .ip import IP, IPSet
from logging import getLogger

log = getLogger(__name__)


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
        self.source_addresses = [
            self._parse_address(e) for e in pie.findall('./source-addresses/*')]
        self.destination_addresses = [
            self._parse_address(e) for e in pie.findall('./destination-addresses/*')]
        self.applications = [
            self._parse_application(e) for e in pie.findall('./applications/application')]
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
        self.destination = IP(rt_elt.find(
            '{http://xml.juniper.net/junos/12.1X44/junos-routing}rt-destination').text)
        for entry in rt_elt.findall('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt-entry'):
            if entry.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}current-active'):
                vias = entry.findall(
                    './/{http://xml.juniper.net/junos/12.1X44/junos-routing}via')
                if vias:
                    self.interface = vias[0].text
                locals = entry.findall(
                    './/{http://xml.juniper.net/junos/12.1X44/junos-routing}nh-local-interface')
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

    def __init__(self, security_policies_xml,
                 route_xml, configuration_security_zones_xml):

        #: list of Policy instances
        self.policies = self._parse_policies(security_policies_xml)

        #: list of Route instances from 'inet.0'
        self.routes = self._parse_routes(route_xml)

        #: list of security zones
        self.zones = self._parse_zones(configuration_security_zones_xml)

    def _parse_policies(self, security_policies_xml):
        log.info("parsing policies")
        sspe = ET.parse(security_policies_xml).getroot()
        policies = []
        for elt in sspe.findall('.//security-context'):
            from_zone = elt.find('./context-information/source-zone-name').text
            to_zone = elt.find(
                './context-information/destination-zone-name').text
            for pol_elt in elt.findall('./policies/policy-information'):
                policy = Policy(from_zone, to_zone, pol_elt)
                policies.append(policy)
        return policies

    def _parse_routes(self, route_xml):
        log.info("parsing routes")
        sre = ET.parse(route_xml).getroot()
        routes = []
        # thanks for the namespaces, Juniper.
        for table in sre.findall('.//{http://xml.juniper.net/junos/12.1X44/junos-routing}route-table'):
            if table.findtext('{http://xml.juniper.net/junos/12.1X44/junos-routing}table-name') == 'inet.0':
                for rt_elt in table.findall('{http://xml.juniper.net/junos/12.1X44/junos-routing}rt'):
                    routes.append(Route(rt_elt))
                return routes
        return []

    def _parse_zones(self, configuration_security_zones_xml):
        log.info("parsing zones")
        scsze = ET.parse(configuration_security_zones_xml).getroot()
        zones = []
        for sz in scsze.findall('.//security-zone'):
            zones.append(Zone(sz))
        return zones
