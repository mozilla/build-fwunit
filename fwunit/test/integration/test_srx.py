# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.srx import scripts
from nose.tools import eq_
import mock
from fwunit.ip import IP, IPSet
from fwunit.types import Rule
from fwunit.test.util.srx_xml import route_xml
from fwunit.test.util.srx_xml import zones_xml
from fwunit.test.util.srx_xml import policy_xml
from fwunit.test.util.srx_xml import policy_tpl
from fwunit.srx import show

# set up to produce fake XML output from the firewall

policies = {
    ('trust', 'trust'): [
        dict(sequence=1, name='ssh--any', src='any', dst='any', app='junos-ssh', action='permit'),
        dict(sequence=10, name='deny', src='any', dst='any', app='any', action='deny'),
    ],
    ('trust', 'untrust'): [
        dict(sequence=1, name='ssh-untrust', src='any', dst='any', app='junos-ssh', action='permit'),
        dict(sequence=2, name='puppet', src='any', dst='puppet', app='puppet', action='permit'),
        dict(sequence=10, name='deny', src='any', dst='any', app='any', action='deny'),
    ],
    ('untrust', 'trust'): [
        dict(sequence=1, name='no-shadow-ping', src='any', dst='shadow', app='junos-ping', action='deny'),
        dict(sequence=2, name='ping', src='any', dst='dmz', app='junos-ping', action='permit'),
        dict(sequence=3, name='admin', src='puppet', dst='trustedhost', app='junos-ssh', action='permit'),
        dict(sequence=4, name='admin', src='any-ipv6', dst='trustedhost', app='junos-ssh', action='permit'),
        dict(sequence=10, name='deny', src='any', dst='any', app='any', action='deny'),
    ],
    ('untrust', 'untrust'): [
        dict(sequence=10, name='deny', src='any', dst='any', app='any', action='deny'),
    ],
}

def fake_show(request):
    if request == 'route':
        return route_xml
    elif request == 'configuration security zones':
        return zones_xml
    elif request.startswith('security policies'):
        request = request.split()
        from_zone, to_zone = request[3], request[5]
        policy_dicts = policies[from_zone, to_zone]
        policy_xmls = [policy_tpl % d for d in policy_dicts]
        return policy_xml % dict(from_zone=from_zone, to_zone=to_zone,
                                 policies='\n'.join(policy_xmls))
    else:
        raise AssertionError("bad request")

conn_patch = mock.patch('fwunit.srx.show.Connection', spec=show.Connection)


def setup_module():
    m = conn_patch.start()
    m().show.side_effect = fake_show


def teardown_module():
    conn_patch.stop()


def test_parse_routes():
    fake_cfg = {
        'firewall': 'fw',
        'ssh_username': 'uu',
        'ssh_password': 'pp',
        'application-map': {'junos-ssh': 'ssh', 'junos-ping': 'ping'},
    }
    rules = scripts.run(fake_cfg, {})
    for r in rules.itervalues():
        r.sort()
    exp = {
        'ping': [
            Rule(src=IPSet([IP('0.0.0.0/0')]) - IPSet([IP('10.0.0.0/8')]),
                 dst=IPSet([IP('10.1.0.0/16')]) - IPSet([IP('10.1.99.99')]),
                 app='ping', name='ping'),
        ],
        'puppet': [
            Rule(src=IPSet([IP('10.0.0.0/8')]), dst=IPSet([IP('9.0.9.2')]), app='puppet',
                 name='puppet'),
        ],
        'ssh': [
            Rule(src=IPSet([IP('9.0.9.2')]), dst=IPSet([IP('10.0.9.2')]), app='ssh',
                 name='admin'),
            Rule(src=IPSet([IP('10.0.0.0/8')]), dst=IPSet([IP('0.0.0.0/0')]), app='ssh',
                 name='ssh--any+ssh-untrust'),
        ],
    }
    eq_(rules, exp)
