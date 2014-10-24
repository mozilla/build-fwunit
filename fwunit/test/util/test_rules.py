# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.ip import IP, IPSet
from fwunit.types import Rule

TEST_RULES = {
    'ping': [
        Rule(src=IPSet([IP('0.0.0.0/0')]) - IPSet([IP('10.0.0.0/8')]),
                dst=IPSet([IP('10.1.0.0/16')]) - IPSet([IP('10.1.99.99')]),
                app='ping', name='ping'),
    ],
    'puppet': [
        Rule(src=IPSet([IP('10.0.0.0/8')]), dst=IPSet([IP('10.0.9.2')]), app='puppet',
                name='puppet'),
    ],
    'ssh': [
        Rule(src=IPSet([IP('9.0.9.2')]), dst=IPSet([IP('10.0.9.2')]), app='ssh',
                name='admin'),
        Rule(src=IPSet([IP('10.0.0.0/8')]), dst=IPSet([IP('0.0.0.0/0')]), app='ssh',
                name='ssh--any+ssh-untrust'),
    ],
}
