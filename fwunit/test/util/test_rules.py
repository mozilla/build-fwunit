# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.types import Rule
from fwunit.test.util import ipset

TEST_RULES = {
    'ping': [
        Rule(src=ipset('0.0.0.0/0') - ipset('10.0.0.0/8'),
             dst=ipset('10.1.0.0/16') - ipset('10.1.99.99'),
             app='ping', name='ping'),
    ],
    'puppet': [
        Rule(src=ipset('10.0.0.0/8'), dst=ipset('10.0.9.2'), app='puppet',
             name='puppet'),
    ],
    'ssh': [
        Rule(src=ipset('9.0.9.2'), dst=ipset('10.0.9.2'), app='ssh',
             name='admin'),
        Rule(src=ipset('10.0.0.0/8'), dst=ipset('0.0.0.0/0'), app='ssh',
             name='ssh--any+ssh-untrust'),
    ],
    '@@other': [
        Rule(src=ipset('1.2.3.4/32'), dst=ipset('0.0.0.0/0'), app='@@other',
             name='admin-access')
    ],
}
