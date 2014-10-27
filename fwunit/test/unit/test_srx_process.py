# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from nose.tools import eq_
from fwunit.srx import parse
from fwunit.srx import process
from fwunit.common import ApplicationMap
from fwunit.test.util import ipset
from fwunit.types import Rule

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
    src_per_policy = {pol: pol.src_addrs for pol in policies}
    dst_per_policy = {pol: pol.dst_addrs for pol in policies}
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
