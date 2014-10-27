# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from nose.tools import eq_
from fwunit.types import Rule
from fwunit.combine import process
from fwunit.test.util import ipset

RULES_10 = {
    'http': [
        # within this ip space
        Rule(src=ipset('10.10.0.0/16'), dst=ipset('10.20.0.0/16'), app='http', name='10->10'),
        # from and to "unmanaged" space
        Rule(src=ipset('30.10.0.0/16'), dst=ipset('10.20.0.0/16'), app='http', name='30->10'),
        Rule(src=ipset('10.10.0.0/16'), dst=ipset('30.20.0.0/16'), app='http', name='10->30'),
        # from and to the 20/8 space
        Rule(src=ipset('20.20.0.0/16', '20.30.0.0/16'),
             dst=ipset('10.20.0.0/16', '10.30.0.0/16'),
             app='http', name='20->10'),
        Rule(src=ipset('10.10.0.0/16', '10.20.0.0/16'),
             dst=ipset('20.10.0.0/16', '20.20.0.0/16'),
             app='http', name='10->20'),
    ],
}

RULES_20 = {
    'http': [
        # within this ip space
        Rule(src=ipset('20.10.0.0/16'), dst=ipset('20.20.0.0/16'), app='http', name='20->20'),
        # from and to "unmanaged" space
        Rule(src=ipset('30.10.0.0/16'), dst=ipset('20.20.0.0/16'), app='http', name='30->20'),
        Rule(src=ipset('20.10.0.0/16'), dst=ipset('30.20.0.0/16'), app='http', name='20->30'),
        # from and to the 10/8 space
        Rule(src=ipset('10.20.0.0/16', '10.30.0.0/16'),
             dst=ipset('20.20.0.0/16', '20.30.0.0/16'),
             app='http', name='10->20'),
        Rule(src=ipset('20.10.0.0/16', '20.20.0.0/16'),
             dst=ipset('10.10.0.0/16', '10.20.0.0/16'),
             app='http', name='20->10'),
    ]
}

def test_combine():
    res = process.combine({
        'ten': dict(rules=RULES_10, ip_space=['10.0.0.0/8']),
        'twenty': dict(rules=RULES_20, ip_space=['20.0.0.0/8']),
    })
    res['http'].sort()
    eq_(res, {
        'http': sorted([
            Rule(src=ipset('10.10.0.0/16'), dst=ipset('10.20.0.0/16', '30.20.0.0/16'),
                 app='http', name='10->10+10->30'), 
            Rule(src=ipset('20.10.0.0/16'), dst=ipset('20.20.0.0/16', '30.20.0.0/16'),
                 app='http', name='20->20+20->30'), 
            Rule(src=ipset('30.10.0.0/16'), dst=ipset('10.20.0.0/16', '20.20.0.0/16'),
                 app='http', name='30->10+30->20'),
            # note that only the intersection of these flows makes it through
            Rule(src=ipset('10.20.0.0/16'), dst=ipset('20.20.0.0/16'),
                 app='http', name='10->20'), 
            Rule(src=ipset('20.20.0.0/16'), dst=ipset('10.20.0.0/16'),
                 app='http', name='20->10'), 
        ]),
    })

