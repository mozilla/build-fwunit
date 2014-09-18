# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import xml.etree.ElementTree as ET
from fwunit.ip import IP, IPSet
from . import parse
from . import show
from nose.tools import eq_
import mock

route_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <route-information xmlns="http://xml.juniper.net/junos/12.1X44/junos-routing">
        <!-- keepalive -->
        <route-table>
            <table-name>inet.0</table-name>
            <destination-count>273</destination-count>
            <total-route-count>410</total-route-count>
            <active-route-count>273</active-route-count>
            <holddown-route-count>0</holddown-route-count>
            <hidden-route-count>0</hidden-route-count>
            <rt junos:style="brief">
                <rt-destination>0.0.0.0/0</rt-destination>
                <rt-entry>
                    <active-tag>*</active-tag>
                    <current-active/>
                    <last-active/>
                    <protocol-name>OSPF</protocol-name>
                    <preference>150</preference>
                    <age junos:seconds="13685128">222w4d 09:25:28</age>
                    <metric>0</metric>
                    <rt-tag>0</rt-tag>
                    <nh>
                        <selected-next-hop/>
                        <to>1.2.3.4</to>
                        <via>reth0</via>
                    </nh>
                </rt-entry>
                <rt-entry>
                    <active-tag> </active-tag>
                    <protocol-name>Static</protocol-name>
                    <preference>200</preference>
                    <age junos:seconds="13685185">22w4d 09:26:25</age>
                    <nh>
                        <selected-next-hop/>
                        <to>1.2.3.5</to>
                        <via>reth0</via>
                    </nh>
                </rt-entry>
            </rt>
        </route-table>
    </route-information>
    <cli>
        <banner>{primary:node1}</banner>
    </cli>
</rpc-reply>
"""

route_xml_11_4R6 = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/11.4R6/junos">
    <route-information xmlns="http://xml.juniper.net/junos/11.4R6/junos-routing">
        <!-- keepalive -->
        <route-table>
            <table-name>inet.0</table-name>
            <destination-count>271</destination-count>
            <total-route-count>418</total-route-count>
            <active-route-count>271</active-route-count>
            <holddown-route-count>0</holddown-route-count>
            <hidden-route-count>0</hidden-route-count>
            <rt junos:style="brief">
                <rt-destination>0.0.0.0/0</rt-destination>
                <rt-entry>
                    <active-tag>*</active-tag>
                    <current-active/>
                    <last-active/>
                    <protocol-name>OSPF</protocol-name>
                    <preference>150</preference>
                    <age junos:seconds="17598334">8w6d 20:45:34</age>
                    <metric>0</metric>
                    <rt-tag>0</rt-tag>
                    <nh>
                        <to>11.111.111.11</to>
                        <via>reth0.10</via>
                    </nh>
                    <nh>
                        <selected-next-hop/>
                        <to>222.22.22.222</to>
                        <via>reth0.11</via>
                    </nh>
                </rt-entry>
                <rt-entry>
                    <active-tag> </active-tag>
                    <protocol-name>Static</protocol-name>
                    <preference>200</preference>
                    <age junos:seconds="26417257">43w4d 18:07:37</age>
                    <nh>
                        <selected-next-hop/>
                        <to>11.111.111.11</to>
                        <via>reth0.10</via>
                    </nh>
                </rt-entry>
            </rt>
        </route-table>
    </route-information>
</rpc-reply>
"""

zones_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <configuration junos:commit-seconds="1409696876" junos:commit-localtime="2014-09-02 22:27:56 UTC" junos:commit-user="dcurado">
            <security>
                <zones>
                    <security-zone>
                        <name>untrust</name>
                        <address-book>
                            <address>
                                <name>host1</name>
                                <ip-prefix>9.0.9.1/32</ip-prefix>
                            </address>
                            <address>
                                <name>host2</name>
                                <ip-prefix>9.0.9.2/32</ip-prefix>
                            </address>
                            <address-set>
                                <name>hosts</name>
                                <address>
                                    <name>host1</name>
                                </address>
                                <address>
                                    <name>host2</name>
                                </address>
                            </address-set>
                        </address-book>
                        <interfaces>
                            <name>reth0</name>
                            <host-inbound-traffic>
                                <system-services>
                                    <name>ping</name>
                                </system-services>
                                <system-services>
                                    <name>traceroute</name>
                                </system-services>
                                <system-services>
                                    <name>bootp</name>
                                </system-services>
                            </host-inbound-traffic>
                        </interfaces>
                    </security-zone>
                    <security-zone>
                        <name>trust</name>
                        <address-book>
                        </address-book>
                        <interfaces>
                            <name>reth0</name>
                            <host-inbound-traffic>
                                <system-services>
                                    <name>ping</name>
                                </system-services>
                            </host-inbound-traffic>
                        </interfaces>
                    </security-zone>
                </zones>
            </security>
    </configuration>
    <cli>
        <banner>{primary:node1}</banner>
    </cli>
</rpc-reply>
"""

zones_empty_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <configuration junos:commit-seconds="1409696876" junos:commit-localtime="2014-09-02 22:27:56 UTC" junos:commit-user="dcurado">
            <security>
                <zones>
                    <security-zone>
                        <name>empty</name>
                    </security-zone>
                </zones>
            </security>
    </configuration>
    <cli>
        <banner>{primary:node1}</banner>
    </cli>
</rpc-reply>
"""

policy_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <multi-routing-engine-results>
        <multi-routing-engine-item>
            <re-name>node1</re-name>
            <security-policies junos:style="brief">
                <security-context>
                    <context-information>
                        <source-zone-name>%(from_zone)s</source-zone-name>
                        <destination-zone-name>%(to_zone)s</destination-zone-name>
                    </context-information>
                    <policies>
                        <policy-information>
                            <policy-name>permit</policy-name>
                            <policy-state>enabled</policy-state>
                            <policy-identifier>2706</policy-identifier>
                            <scope-policy-identifier>0</scope-policy-identifier>
                            <policy-sequence-number>1</policy-sequence-number>
                            <source-addresses junos:style="brief">
                                <source-address>
                                    <address-name>any</address-name>
                                </source-address>
                            </source-addresses>
                            <destination-addresses junos:style="brief">
                                <destination-address>
                                    <address-name>any</address-name>
                                </destination-address>
                            </destination-addresses>
                            <applications junos:style="brief">
                                <application>
                                    <application-name>%(from_zone)s-%(to_zone)s</application-name>
                                </application>
                            </applications>
                            <source-identities junos:style="brief"></source-identities>
                            <policy-action>
                                <action-type>permit</action-type>
                                <policy-tcp-options>
                                    <policy-tcp-options-syn-check>No</policy-tcp-options-syn-check>
                                    <policy-tcp-options-sequence-check>No</policy-tcp-options-sequence-check>
                                </policy-tcp-options>
                            </policy-action>
                            <policy-application-services></policy-application-services>
                        </policy-information>
                    </policies>
                </security-context>
            </security-policies>
        </multi-routing-engine-item>
        
    </multi-routing-engine-results>
    <cli>
        <banner>{primary:node1}</banner>
    </cli>
</rpc-reply>
"""


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
    eq_(z.addresses.keys(), ['any'])

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
    eq_(sorted(zones)[0].addresses['host1'], IPSet([IP('9.0.9.1')]))


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
