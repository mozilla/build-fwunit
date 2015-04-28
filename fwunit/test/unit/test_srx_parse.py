# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import xml.etree.ElementTree as ET
from fwunit.ip import IP, IPSet
from fwunit.srx import parse
from nose.tools import eq_
from fwunit.test.util.srx_xml import route_xml_11_4R6
from fwunit.test.util.srx_xml import zones_empty_xml
from fwunit.test.util.srx_xml import FakeSRX


def parse_xml(xml, elt_path=None):
    elt = parse.strip_namespaces(ET.fromstring(xml))
    if elt_path:
        elt = elt.find(elt_path)
    return elt


def test_parse_zone():
    f = FakeSRX()
    z = f.add_zone('untrust')
    f.add_address(z, 'host1', '9.0.9.1/32')
    f.add_address(z, 'host2', '9.0.9.2/32')
    f.add_address(z, 'puppet', '9.0.9.3/32')
    f.add_address_set(z, 'hosts', 'host1', 'host2')
    f.add_interface(z, 'reth0')

    elt = parse_xml(
        f.fake_show('configuration security zones'), './/security-zone')
    z = parse.Zone._from_xml(elt)
    eq_(z.interfaces, ['reth0'])
    eq_(sorted(z.addresses.keys()),
        sorted(['any', 'any-ipv4', 'any-ipv6', 'host1', 'host2', 'hosts', 'puppet']))
    eq_(z.addresses['any'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv4'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv6'], IPSet([]))
    eq_(z.addresses['host1'], IPSet([IP('9.0.9.1')]))
    eq_(z.addresses['host2'], IPSet([IP('9.0.9.2')]))
    eq_(z.addresses['puppet'], IPSet([IP('9.0.9.3')]))
    eq_(z.addresses['hosts'], IPSet([IP('9.0.9.1'), IP('9.0.9.2')]))


def test_parse_zone_no_sets():
    f = FakeSRX()
    z = f.add_zone('untrust')
    f.add_address(z, 'trustedhost', '10.0.9.2/32')
    f.add_address(z, 'dmz', '10.1.0.0/16')
    f.add_address(z, 'shadow', '10.1.99.99/32')
    f.add_interface(z, 'reth1')

    elt = parse_xml(
        f.fake_show('configuration security zones'), './/security-zone')
    z = parse.Zone._from_xml(elt)
    eq_(z.interfaces, ['reth1'])
    eq_(sorted(z.addresses.keys()),
        sorted(['any', 'any-ipv4', 'any-ipv6', 'trustedhost', 'dmz', 'shadow']))
    eq_(z.addresses['any'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv4'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv6'], IPSet([]))
    eq_(z.addresses['trustedhost'], IPSet([IP('10.0.9.2')]))
    eq_(z.addresses['dmz'], IPSet([IP('10.1.0.0/16')]))
    eq_(z.addresses['shadow'], IPSet([IP('10.1.99.99')]))


def test_parse_global_policy():
    f = FakeSRX()
    f.add_policy('global',
                 dict(sequence=1, name='global-ping', src='any', dst='any',
                      app='ping', action='permit'))
    f.add_policy('global',
                 dict(sequence=10, name='global-deny', src='any', dst='any',
                      app='any', action='deny'))

    elt = parse_xml(
        f.fake_show('security policies global'), './/security-context')
    policies = [parse.Policy._from_xml(None, None, e) for e in elt.findall('./policies/policy-information')]
    eq_(policies[0].from_zone, None)
    eq_(policies[0].to_zone, None)
    eq_(policies[0].to_zone, None)
    eq_(policies[0].enabled, True)
    eq_(policies[0].sequence, 1)
    eq_(policies[0].source_addresses, ['any'])
    eq_(policies[0].destination_addresses, ['any'])
    eq_(policies[0].applications, ['ping'])
    eq_(policies[0].action, 'permit')
    eq_(policies[0].from_zone, None)
    eq_(policies[1].to_zone, None)
    eq_(policies[1].to_zone, None)
    eq_(policies[1].enabled, True)
    eq_(policies[1].sequence, 10)
    eq_(policies[1].source_addresses, ['any'])
    eq_(policies[1].destination_addresses, ['any'])
    eq_(policies[1].applications, ['any'])
    eq_(policies[1].action, 'deny')


def test_parse_addrbook_global():
    f = FakeSRX()
    ab = f.add_addrbook('global')
    f.add_address(ab, 'host1', '9.0.9.1/32')
    f.add_address(ab, 'host2', '9.0.9.2/32')
    f.add_address_set(ab, 'hosts', 'host1', 'host2')

    elt = parse_xml(
        f.fake_show('configuration security address-book'), './/address-book')
    z = parse.AddressBook._from_xml(elt)
    eq_(z.attaches, [])
    eq_(sorted(z.addresses.keys()),
        sorted(['any', 'any-ipv4', 'any-ipv6', 'host1', 'host2', 'hosts']))
    eq_(z.addresses['any'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv4'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv6'], IPSet([]))
    eq_(z.addresses['host1'], IPSet([IP('9.0.9.1')]))
    eq_(z.addresses['host2'], IPSet([IP('9.0.9.2')]))
    eq_(z.addresses['hosts'], IPSet([IP('9.0.9.1'), IP('9.0.9.2')]))

def test_parse_addrbook_attached():
    f = FakeSRX()
    ab = f.add_addrbook('general-stuff')
    f.add_address(ab, 'trustedhost', '10.0.9.2/32')
    f.add_attach(ab, 'untrust')
    f.add_attach(ab, 'trust')

    elt = parse_xml(
        f.fake_show('configuration security address-book'), './/address-book')
    z = parse.AddressBook._from_xml(elt)
    eq_(z.attaches, ['untrust', 'trust'])
    eq_(sorted(z.addresses.keys()),
        sorted(['any', 'any-ipv4', 'any-ipv6', 'trustedhost']))
    eq_(z.addresses['any'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv4'], IPSet([IP('0.0.0.0/0')]))
    eq_(z.addresses['any-ipv6'], IPSet([]))
    eq_(z.addresses['trustedhost'], IPSet([IP('10.0.9.2')]))


def test_parse_zones_empty():
    elt = parse_xml(zones_empty_xml, './/security-zone')
    z = parse.Zone._from_xml(elt)
    eq_(z.interfaces, [])
    eq_(sorted(z.addresses.keys()), sorted(['any', 'any-ipv6', 'any-ipv4']))


def test_parse_route_11_4R6():
    elt = parse_xml(route_xml_11_4R6, './/rt')
    r = parse.Route._from_xml(elt)
    eq_(r.destination, IP('0.0.0.0/0'))
    eq_(r.interface, 'reth0.10')
    eq_(r.is_local, False)
