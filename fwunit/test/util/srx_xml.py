# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

## fake XML results derived from the output of a Juniper SRX

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
                            <address>
                                <name>puppet</name>
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
                            <address>
                                <name>trustedhost</name>
                                <ip-prefix>10.0.9.2/32</ip-prefix>
                            </address>
                            <address>
                                <name>dmz</name>
                                <ip-prefix>10.1.0.0/16</ip-prefix>
                            </address>
                            <address>
                                <name>shadow</name>
                                <ip-prefix>10.1.99.99/32</ip-prefix>
                            </address>
                        </address-book>
                        <interfaces>
                            <name>reth1</name>
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
