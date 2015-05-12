# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import mock
from fwunit.srx import show

# fake XML results derived from the output of a Juniper SRX

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
            <rt junos:style="brief">
                <rt-destination>10.0.0.0/8</rt-destination>
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
                        <via>reth1</via>
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

route_xml_blackhole = """\
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
                <rt-destination>20.0.0.0/8</rt-destination>
                <rt-entry>
                    <active-tag>*</active-tag>
                    <current-active/>
                    <last-active/>
                    <protocol-name>Aggregate</protocol-name>
                    <preference>130</preference>
                    <age junos:seconds="33111187">54w5d 05:33:07</age>
                    <nh-type>Reject</nh-type>
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
%(zones)s
                </zones>
            </security>
    </configuration>
    <cli>
        <banner>{primary:node1}</banner>
    </cli>
</rpc-reply>
"""

zone_tpl = """\
        <security-zone>
            <name>%(name)s</name>
            <address-book>
%(addresses)s
%(address_sets)s
            </address-book>
            <interfaces>
%(interfaces)s
            </interfaces>
        </security-zone>
"""

address_tpl = """\
        <address>
            <name>%(name)s</name>
            <ip-prefix>%(prefix)s</ip-prefix>
        </address>
"""

address_set_tpl = """\
        <address-set>
            <name>%(name)s</name>
%(addresses)s
        </address-set>
"""

address_set_elt_tpl = """\
        <address>
            <name>%(name)s</name>
        </address>
"""

interface_tpl = """\
        <interfaces>
            <name>%(name)s</name>
            <host-inbound-traffic>
                <system-services>
                    <name>ping</name>
                </system-services>
            </host-inbound-traffic>
        </interfaces>
"""

addrbooks_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <configuration junos:commit-seconds="1430170546" junos:commit-localtime="2015-04-27 21:35:46 UTC" junos:commit-user="root">
            <security>
%(addrbooks)s
            </security>
    </configuration>
    <cli>
        <banner></banner>
    </cli>
</rpc-reply>
"""

addrbook_tpl = """\
        <address-book>
            <name>%(name)s</name>
%(addresses)s
%(address_sets)s
%(attaches)s
        </address-book>
"""

addrbook_attaches_tpl = """\
        <attach>
%(attaches)s
        </attach>
"""

addrbook_attach_tpl = """\
        <zone>
            <name>%(name)s</name>
        </zone>
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
%(policies)s
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

no_global_policy_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <security-policies junos:style="brief">
    </security-policies>
    <cli>
        <banner></banner>
    </cli>
</rpc-reply>
"""

global_policy_xml = """\
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <security-policies junos:style="brief">
        <security-context>
            <context-information>
                <global-context/>
            </context-information>
            <policies>
%(policies)s
            </policies>
        </security-context>
    </security-policies>
    <cli>
        <banner></banner>
    </cli>
</rpc-reply>
"""

policy_tpl = """
    <policy-information>
        <policy-name>%(name)s</policy-name>
        <policy-state>enabled</policy-state>
        <policy-identifier>2706</policy-identifier>
        <scope-policy-identifier>0</scope-policy-identifier>
        <policy-sequence-number>%(sequence)s</policy-sequence-number>
        <source-addresses junos:style="brief">
            <source-address>
                <address-name>%(src)s</address-name>
            </source-address>
        </source-addresses>
        <destination-addresses junos:style="brief">
            <destination-address>
                <address-name>%(dst)s</address-name>
            </destination-address>
        </destination-addresses>
        <applications junos:style="brief">
            <application>
                <application-name>%(app)s</application-name>
            </application>
        </applications>
        <source-identities junos:style="brief"></source-identities>
        <policy-action>
            <action-type>%(action)s</action-type>
            <policy-tcp-options>
                <policy-tcp-options-syn-check>No</policy-tcp-options-syn-check>
                <policy-tcp-options-sequence-check>No</policy-tcp-options-sequence-check>
            </policy-tcp-options>
        </policy-action>
        <policy-application-services></policy-application-services>
    </policy-information>
"""

# set up to produce fake XML output from the firewall


class FakeSRX(object):

    def __init__(self):
        self.policies = {}
        self.zones = {}
        self.address_books = {}

    def fake_show(self, request):
        if request == 'route':
            return route_xml
        elif request == 'configuration security address-book':
            addrbook_xmls = []
            for ab_name, info in self.address_books.iteritems():
                addresses = [address_tpl % addr
                             for addr in info['addresses']]
                addresses = '\n'.join(addresses)
                address_sets = []
                for addrset in info['address-sets']:
                    elts = [address_set_elt_tpl % dict(name=name)
                            for name in addrset[1]]
                    address_sets.append(
                        address_set_tpl % dict(name=addrset[0],
                                               addresses='\n'.join(elts)))
                address_sets = '\n'.join(address_sets)
                if info['attach']:
                    attaches = [addrbook_attach_tpl % dict(name=name)
                                for name in info['attach']]
                    attaches = '\n'.join(attaches)
                    attaches = addrbook_attaches_tpl % dict(attaches=attaches)
                else:
                    attaches = ''
                addrbook_xmls.append(addrbook_tpl % dict(
                    name=ab_name, addresses=addresses, address_sets=address_sets,
                    attaches=attaches))
            return addrbooks_xml % dict(addrbooks='\n'.join(addrbook_xmls))
        elif request == 'configuration security zones':
            zone_xmls = []
            for zone_name, info in self.zones.iteritems():
                addresses = [address_tpl % addr
                             for addr in info['addresses']]
                addresses = '\n'.join(addresses)
                address_sets = []
                for addrset in info['address-sets']:
                    elts = [address_set_elt_tpl % dict(name=name)
                            for name in addrset[1]]
                    address_sets.append(
                        address_set_tpl % dict(name=addrset[0],
                                               addresses='\n'.join(elts)))
                address_sets = '\n'.join(address_sets)
                interfaces = [interface_tpl % dict(name=name)
                              for name in info['interfaces']]
                interfaces = '\n'.join(interfaces)
                zone_xmls.append(zone_tpl % dict(
                    name=zone_name, addresses=addresses,
                    address_sets=address_sets,
                    interfaces=interfaces))
            return zones_xml % dict(zones='\n'.join(zone_xmls))
        elif request.startswith('security policies'):
            if request == 'security policies global':
                if 'global' in self.policies:
                    policy_dicts = self.policies['global']
                    policy_xmls = [policy_tpl % d for d in policy_dicts]
                    return global_policy_xml % dict(policies='\n'.join(policy_xmls))
                else:
                    return no_global_policy_xml
            else:
                request = request.split()
                from_zone, to_zone = request[3], request[5]
                try:
                    policy_dicts = self.policies[from_zone, to_zone]
                except KeyError:
                    policy_dicts = []
                policy_xmls = [policy_tpl % d for d in policy_dicts]
                return policy_xml % dict(from_zone=from_zone, to_zone=to_zone,
                                        policies='\n'.join(policy_xmls))
        else:
            raise AssertionError("bad request")

    def install(self):
        self.conn_patch = mock.patch(
            'fwunit.srx.show.Connection', spec=show.Connection)
        m = self.conn_patch.start()
        m().show.side_effect = self.fake_show

    def uninstall(self):
        self.conn_patch.stop()

    def add_zone(self, name):
        z = {'addresses': [], 'address-sets': [], 'interfaces': []}
        self.zones[name] = z
        return z

    def add_addrbook(self, name):
        addrbook = {'addresses': [], 'address-sets': [], 'attach': []}
        self.address_books[name] = addrbook
        return addrbook

    def add_attach(self, addrbook, zone_name):
        addrbook['attach'].append(zone_name)

    def add_address(self, container, name, prefix):
        # container can be a zone or addrbook
        container['addresses'].append({'name': name, 'prefix': prefix})

    def add_address_set(self, container, name, *names):
        # container can be a zone or addrbook
        container['address-sets'].append((name, list(names)))

    def add_interface(self, z, name):
        z['interfaces'].append(name)

    def add_policy(self, name, policy):
        self.policies.setdefault(name, []).append(policy)
