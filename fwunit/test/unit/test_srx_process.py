# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from nose.tools import eq_
from fwunit.srx import parse
from fwunit.srx import process
from fwunit.common import ApplicationMap
from fwunit.test.util import ipset
from fwunit.types import Rule
from fwunit import IP

APP_MAP = ApplicationMap(dict(application_map={'junos-ssh': 'ssh'}))
ZONE_NETS = {
    'pvt': ipset('192.168.0.0/16'),
    'dmz': ipset('10.0.0.0/8'),
    'pub': ipset('128.135.0.00/16'),
}

def mkpol(**kwargs):
    kwargs.setdefault('action', 'permit')
    kwargs.setdefault('enabled', True)
    kwargs.setdefault('sequence', 1)
    kwargs['source_addresses'] = kwargs.pop('src_addrs')
    kwargs['destination_addresses'] = kwargs.pop('dst_addrs')
    pol = parse.Policy()
    for k, v in kwargs.iteritems():
        setattr(pol, k, v)
    return pol

def call_process_rules(app_map, policies, zone_nets):
    # calculate a few of the extra inputs
    policies_by_zone_pair = {}
    for pol in policies:
        policies_by_zone_pair.setdefault(
            (pol.from_zone, pol.to_zone), []).append(pol)
    src_per_policy = {pol: pol.source_addresses for pol in policies}
    dst_per_policy = {pol: pol.destination_addresses for pol in policies}
    res = process.process_rules(app_map, policies, zone_nets,
                                policies_by_zone_pair, src_per_policy,
                                dst_per_policy)
    [ruleset.sort() for ruleset in res.itervalues()]
    return res

def test_process_rules_any_app():
    # test basic functionality + the "any" app
    policies = [
        mkpol(name='dbssh', from_zone='pvt', to_zone='pvt',
            src_addrs=ipset('192.168.1.2/31'), dst_addrs=ipset('0.0.0.0/0'),
            applications=['junos-ssh', 'junos-ping'], sequence=1),
        mkpol(name='admin', from_zone='pvt', to_zone='pvt',
            src_addrs=ipset('192.168.1.128/32'), dst_addrs=ipset('0.0.0.0/0'),
            applications=['any'], sequence=2),
        mkpol(name='admin', from_zone='pvt', to_zone='dmz',
            src_addrs=ipset('192.168.1.128/32'), dst_addrs=ipset('0.0.0.0/0'),
            applications=['any']),
        mkpol(name='admin', from_zone='pvt', to_zone='pub',
            src_addrs=ipset('192.168.1.128/32'), dst_addrs=ipset('0.0.0.0/0'),
            applications=['any']),
        mkpol(name='http', from_zone='pub', to_zone='dmz',
            src_addrs=ipset('0.0.0.0/0'), dst_addrs=ipset('10.1.10.0/24'),
            applications=['web']),
        mkpol(name='db', from_zone='dmz', to_zone='pvt',
            src_addrs=ipset('10.1.10.0/24'), dst_addrs=ipset('192.168.1.2/31'),
            applications=['db']),
    ]
    res = call_process_rules(APP_MAP, policies, ZONE_NETS)
    exp = {
        'junos-ping': [
            Rule(src=ipset('192.168.1.128'),
                 dst=ipset('10.0.0.0/8', '128.135.0.0/16', '192.168.0.0/16'),
                 app='junos-ping', name='admin'),
            Rule(src=ipset('192.168.1.2/31'), dst=ipset('192.168.0.0/16'), app='junos-ping', name='dbssh'),
        ],
        'web': [
            Rule(src=ipset('192.168.1.128'),
                 dst=ipset('10.0.0.0/8', '128.135.0.0/16', '192.168.0.0/16'),
                 app='web', name='admin'),
            Rule(src=ipset('128.135.0.0/16'), dst=ipset('10.1.10.0/24'), app='web', name='http'),
        ],
        'db': [
            Rule(src=ipset('192.168.1.128'),
                 dst=ipset('10.0.0.0/8', '128.135.0.0/16', '192.168.0.0/16'),
                 app='db', name='admin'),
            Rule(src=ipset('10.1.10.0/24'), dst=ipset('192.168.1.2/31'), app='db', name='db'),
        ],
        'junos-ssh': [
            Rule(src=ipset('192.168.1.128'),
                 dst=ipset('10.0.0.0/8', '128.135.0.0/16', '192.168.0.0/16'),
                 app='junos-ssh', name='admin'),
            Rule(src=ipset('192.168.1.2/31'), dst=ipset('192.168.0.0/16'), app='junos-ssh', name='dbssh'),
        ],
        '@@other': [
            Rule(src=ipset('192.168.1.128'),
                 dst=ipset('10.0.0.0/8', '128.135.0.0/16', '192.168.0.0/16'),
                 app='@@other', name='admin'),
        ],
    }
    [ruleset.sort() for ruleset in exp.itervalues()]
    eq_(res, exp)


def test_process_global_priority():
    # test the relative priority of "regular" (per-zone) and global policies
    policies = [
        mkpol(name='ok', from_zone='pvt', to_zone='pub',
            src_addrs=ipset('192.168.1.2/31'), dst_addrs=ipset('0.0.0.0/0'),
            applications=['junos-ssh'], sequence=100),
        mkpol(name='deny-all-global', from_zone=None, to_zone=None,
            src_addrs=ipset('0.0.0.0/0'), dst_addrs=ipset('0.0.0.0/0'),
            applications=['junos-ssh'], sequence=3, action='deny'),
        mkpol(name='ok-global', from_zone=None, to_zone=None,
            src_addrs=ipset('192.168.1.128/32'), dst_addrs=ipset('128.135.0.0/16'),
            applications=['junos-ssh'], sequence=1),
    ]
    res = call_process_rules(APP_MAP, policies, ZONE_NETS)
    exp = {
        'junos-ssh': [
            Rule(src=ipset('192.168.1.128/32', '192.168.1.2/31'),
                 dst=ipset('128.135.0.0/16'),
                 app='junos-ssh', name='ok+ok-global'),
        ],
    }
    [ruleset.sort() for ruleset in exp.itervalues()]
    eq_(res, exp)


def mkroute(**kwargs):
    kwargs['destination'] = IP(kwargs['destination'])
    kwargs.setdefault('is_local', False)
    rt = parse.Route()
    for k, v in kwargs.iteritems():
        setattr(rt, k, v)
    return rt


def test_process_interface_ips():
    routes = [
        # reth2 is the route to the Internet
        mkroute(destination="0.0.0.0/0", interface='reth2'),
        # reth1 is the gateway to the rest of the private space
        mkroute(destination="10.0.0.0/8", interface='reth1'),
        # reth7 is the peer link to some other private /16's
        mkroute(destination="10.128.0.0/16", interface='reth7'),
        mkroute(destination="10.130.0.0/15", interface='reth7'),
        # 10.129.0.0/16 is ours, but has only one active subnet,
        # with the rest blackholed
        mkroute(destination="10.129.0.0/16", reject=True),
        mkroute(destination="10.129.210.0/24",
                interface='reth0.210', is_local=True),
    ]
    interface_ips = process.process_interface_ips(routes)
    exp = {
        'reth0.210': ipset('10.129.210.0/24'),
        'reth1': ipset('10.0.0.0/8') - ipset('10.128.0.0/14'), # 10.{128-131}
        'reth2': ipset('0.0.0.0/0') - ipset('10.0.0.0/8'),
        'reth7': ipset('10.128.0.0/16') + ipset('10.130.0.0/15'),
    }
    eq_(interface_ips, exp)
