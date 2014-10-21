# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import xml.etree.ElementTree as ET
from fwunit.ip import IP, IPSet
from fwunit.srx import parse
from fwunit.srx import show
from nose.tools import eq_
from fwunit.test.util.srx_xml import route_xml
from fwunit.test.util.srx_xml import route_xml_11_4R6
from fwunit.test.util.srx_xml import zones_xml
from fwunit.test.util.srx_xml import zones_empty_xml
from fwunit.test.util.srx_xml import policy_xml
import mock


def fake_show(request):
    if request == 'route':
        return route_xml
    elif request == 'configuration security zones':
        return zones_xml
    elif request.startswith('security policies'):
        request = request.split()
        from_zone, to_zone = request[3], request[5]
        return policy_xml % dict(from_zone=from_zone, to_zone=to_zone)
    else:
        raise AssertionError("bad request")

fake_cfg = dict(firewall='fw', ssh_username='uu', ssh_password='pp')
conn_patch = mock.patch('fwunit.srx.show.Connection', spec=show.Connection)


def parse_xml(xml, elt_path=None):
    elt = parse.strip_namespaces(ET.fromstring(xml))
    if elt_path:
        elt = elt.find(elt_path)
    return elt


def setup_module():
    m = conn_patch.start()
    m().show.side_effect = fake_show


def teardown_module():
    conn_patch.stop()

#
# Unit tests
#


def test_parse_zones_empty():
    elt = parse_xml(zones_empty_xml, './/security-zone')
    z = parse.Zone._from_xml(elt)
    eq_(z.interfaces, [])
    eq_(sorted(z.addresses.keys()), sorted(['any', 'any-ipv6']))

def test_parse_route_11_4R6():
    elt = parse_xml(route_xml_11_4R6, './/rt')
    r = parse.Route._from_xml(elt)
    eq_(r.destination, IP('0.0.0.0/0'))
    eq_(r.interface, 'reth0.10')
    eq_(r.is_local, False)

#
# Integration-style tests
#
# These use Firewall._parse_*, passing in raw XML


def test_parse_routes():
    fw = parse.Firewall()
    routes = fw._parse_routes(show.Connection(fake_cfg))
    eq_([str(r) for r in routes], ['0.0.0.0/0 via reth0'])


def test_parse_zones():
    fw = parse.Firewall()
    zones = fw._parse_zones(show.Connection(fake_cfg))
    eq_(sorted([str(r) for r in zones]),
        sorted(["untrust on ['reth0']", "trust on ['reth0']"]))
    eq_(sorted(z.addresses for z in zones), sorted([{
            'any': IPSet([IP('0.0.0.0/0')]),
            'any-ipv6': IPSet([]),
        }, {
            'any': IPSet([IP('0.0.0.0/0')]),
            'any-ipv6': IPSet([]),
            'hosts': IPSet([IP('9.0.9.1'), IP('9.0.9.2')]),
            'host1': IPSet([IP('9.0.9.1')]),
            'host2': IPSet([IP('9.0.9.2')]),
        }]))


def test_parse_policies():
    fw = parse.Firewall()
    fw.zones = fw._parse_zones(show.Connection(fake_cfg))
    policies = fw._parse_policies(show.Connection(fake_cfg))
    eq_(sorted([str(p) for p in policies]),
        sorted([
            "permit trust:['any'] -> trust:['any'] : ['trust-trust']",
            "permit trust:['any'] -> untrust:['any'] : ['trust-untrust']",
            "permit untrust:['any'] -> trust:['any'] : ['untrust-trust']",
            "permit untrust:['any'] -> untrust:['any'] : ['untrust-untrust']",
        ]))
