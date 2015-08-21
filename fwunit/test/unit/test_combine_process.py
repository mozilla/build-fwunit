# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.types import Rule
from fwunit.combine import process
from fwunit.common import simplify_rules
from fwunit.test.util import ipset
from nose.tools import eq_
import contextlib


@contextlib.contextmanager
def no_simplify():
    # simplifying makes tests harder!
    process.simplify_rules = lambda r: r
    try:
        yield
    finally:
        process.simplify_rules = simplify_rules

routes = {
    ('ord', 'ord'): ['fw1.ord'],
    ('ord', 'lga'): ['fw1.ord', 'fw1.lga'],
    ('lga', 'lga'): ['fw1.lga'],
    ('lga', 'ord'): ['fw1.ord', 'fw1.lga'],
}

def test_one_address_space():
    rules = {'app': [
        Rule(ipset('1.2.3.4'), ipset('1.7.7.7'), 'app', 'p2p'),
        Rule(ipset('1.2.5.0/24'), ipset('1.7.7.7'), 'app', 'net'),
    ]}
    with no_simplify():
        result = process.combine(
            {'nyc': ipset('1.0.0.0/8')},
            {('nyc', 'nyc'): ['fw1.nyc']},
            {'fw1.nyc': rules})
        eq_(sorted(result), sorted(rules))


def test_other_app():
    ord_rules = {
        'ordonly': [
            Rule(ipset('1.1.0.0'), ipset('1.1.9.9'), 'ordonly', 'ordonly'),
        ],
        'inboth': [
            Rule(ipset('1.1.8.8'), ipset('1.1.9.9'), 'inboth', 'inboth_ord'),
        ],
        '@@other': [
            Rule(ipset('1.1.0.0'), ipset('1.1.9.9'), '@@other', 'ordother'),
        ],
    }
    lga_rules = {
        'lgaonly': [
            Rule(ipset('65.1.0.0'), ipset('65.1.9.9'), 'lgaonly', 'lgaonly'),
        ],
        'inboth': [
            Rule(ipset('65.1.8.8'), ipset('65.1.9.9'), 'inboth', 'inboth_lga'),
        ],
        '@@other': [
            Rule(ipset('65.1.0.0'), ipset('65.1.9.9'), '@@other', 'lgaother'),
        ],
    }
    address_spaces = {
        'ord': ipset('0.0.0.0/2'),
        'lga': ipset('64.0.0.0/2'),
    }
    sources = {'fw1.ord': ord_rules, 'fw1.lga': lga_rules}
    with no_simplify():
        result = process.combine(address_spaces, routes, sources)
        for apprules in result.itervalues():
            apprules.sort()
        eq_(result, {
            'ordonly': sorted([
                Rule(ipset('1.1.0.0'), ipset('1.1.9.9'), 'ordonly', 'ordonly'),
                Rule(ipset('65.1.0.0'), ipset('65.1.9.9'), 'ordonly', 'lgaother'),
            ]),
            'lgaonly': sorted([
                Rule(ipset('65.1.0.0'), ipset('65.1.9.9'), 'lgaonly', 'lgaonly'),
                Rule(ipset('1.1.0.0'), ipset('1.1.9.9'), 'lgaonly', 'ordother'),
            ]),
            'inboth': sorted([
                Rule(ipset('1.1.8.8'), ipset('1.1.9.9'), 'inboth', 'inboth_ord'),
                Rule(ipset('65.1.8.8'), ipset('65.1.9.9'), 'inboth', 'inboth_lga'),
            ]),
            '@@other': sorted([
                Rule(ipset('1.1.0.0'), ipset('1.1.9.9'), '@@other', 'ordother'),
                Rule(ipset('65.1.0.0'), ipset('65.1.9.9'), '@@other', 'lgaother'),
            ]),
        })


def test_nonoverlapping_rules():
    lga_rules = {'app': [
        Rule(ipset('1.2.5.0/24'), ipset('2.2.5.0/24'), 'app', 'lga'),
    ]}
    ord_rules = {'app': [
        Rule(ipset('2.7.7.0/24'), ipset('1.7.7.0/24'), 'app', 'ord'),
    ]}
    address_spaces = {
        'ord': ipset('2.0.0.0/8'),
        'lga': ipset('1.0.0.0/8'),
    }
    sources = {'fw1.ord': ord_rules, 'fw1.lga': lga_rules}
    with no_simplify():
        result = process.combine(address_spaces, routes, sources)
        eq_(result, {})


def test_identical_rules():
    rules = {'app': [
        Rule(ipset('2.7.7.0/24'), ipset('1.7.7.0/24'), 'app', 'lga-ord'),
    ]}
    address_spaces = {
        'lga': ipset('1.0.0.0/8'),
        'ord': ipset('2.0.0.0/8'),
    }
    sources = {'fw1.ord': rules, 'fw1.lga': rules}
    with no_simplify():
        result = process.combine(address_spaces, routes, sources)
        eq_(result, rules)


def test_overlapping_rules():
    lga_rules = {'app': [
        Rule(ipset('1.1.0.0/16'), ipset('2.0.0.0/8'), 'app', 'lga'),
    ]}
    ord_rules = {'app': [
        Rule(ipset('1.0.0.0/8'), ipset('2.1.0.0/16'), 'app', 'ord'),
    ]}
    address_spaces = {
        'lga': ipset('1.0.0.0/8'),
        'ord': ipset('2.0.0.0/8'),
    }
    sources = {'fw1.ord': ord_rules, 'fw1.lga': lga_rules}

    with no_simplify():
        result = process.combine(address_spaces, routes, sources)
        eq_(result, {'app': [
            # takes the intersection of both rules:
            Rule(ipset('1.1.0.0/16'), ipset('2.1.0.0/16'), 'app', 'lga+ord'),
        ]})


def test_limited_by_space():
    lax_rules = {'app': [
    ]}
    lga_rules = {'app': [
        # /7 covers both lax and lga
        Rule(ipset('0.0.0.0/7'), ipset('2.0.0.0/8'), 'app', 'lga'),
    ]}
    ord_rules = {'app': [
        Rule(ipset('0.0.0.0/7'), ipset('2.0.0.0/8'), 'app', 'ord'),
    ]}
    address_spaces = {
        'lax': ipset('0.0.0.0/8'),
        'lga': ipset('1.0.0.0/8'),
        'ord': ipset('2.0.0.0/8'),
    }
    routes = {
        ('lax', 'lax'): ['fw1.lax'],
        ('lax', 'lga'): ['fw1.lga', 'fw1.lax'],
        ('lax', 'ord'): ['fw1.ord', 'fw1.lax'],
        ('lga', 'lax'): ['fw1.lax', 'fw1.lga'],
        ('lga', 'lga'): ['fw1.lga'],
        ('lga', 'ord'): ['fw1.ord', 'fw1.lga'],
        ('ord', 'lax'): ['fw1.ord', 'fw1.lax'],
        ('ord', 'lga'): ['fw1.ord', 'fw1.lga'],
        ('ord', 'ord'): ['fw1.ord'],
    }
    sources = {'fw1.ord': ord_rules, 'fw1.lga': lga_rules, 'fw1.lax': lax_rules}
    with no_simplify():
        result = process.combine(address_spaces, routes, sources)
        eq_(result, {'app': [
            # only lga's address space is allowed
            Rule(ipset('1.0.0.0/8'), ipset('2.0.0.0/8'), 'app', 'lga+ord'),
        ]})


def test_multiple_matches():
    lga_rules = {'app': [
        Rule(ipset('1.1.1.1'), ipset('2.0.0.0/8'), 'app', 'one'),
        Rule(ipset('1.1.1.2'), ipset('2.0.0.0/8'), 'app', 'two'),
        Rule(ipset('1.1.1.3'), ipset('2.0.0.0/8'), 'app', 'three'),
    ]}
    ord_rules = {'app': [
        Rule(ipset('1.0.0.0/8'), ipset('2.7.8.8'), 'app', 'eight'),
        Rule(ipset('1.0.0.0/8'), ipset('2.7.8.9'), 'app', 'nine'),
    ]}
    address_spaces = {
        'lga': ipset('1.0.0.0/8'),
        'ord': ipset('2.0.0.0/8'),
    }
    sources = {'fw1.ord': ord_rules, 'fw1.lga': lga_rules}
    with no_simplify():
        result = process.combine(address_spaces, routes, sources)
        eq_(sorted(result['app']), sorted([
            # takes the intersection of all rules:
            Rule(src=ipset('1.1.1.1'), dst=ipset('2.7.8.8'), app='app', name='eight+one'),
            Rule(src=ipset('1.1.1.1'), dst=ipset('2.7.8.9'), app='app', name='nine+one'),
            Rule(src=ipset('1.1.1.2'), dst=ipset('2.7.8.8'), app='app', name='eight+two'),
            Rule(src=ipset('1.1.1.2'), dst=ipset('2.7.8.9'), app='app', name='nine+two'),
            Rule(src=ipset('1.1.1.3'), dst=ipset('2.7.8.8'), app='app', name='eight+three'),
            Rule(src=ipset('1.1.1.3'), dst=ipset('2.7.8.9'), app='app', name='nine+three')
        ]))


def test_rules_from_to_empty():
    eq_(process.rules_from_to([], ipset('1.0.0.0/8'), ipset('2.0.0.0/8')),
        [])


def test_rules_from_to_no_match_src():
    rules = [
        Rule(src=ipset('3.0.0.0/24'), dst=ipset('2.0.0.0/8'), app='app', name='r'),
    ]
    eq_(process.rules_from_to(rules, ipset('1.0.0.0/8'), ipset('2.0.0.0/8')),
        [])


def test_rules_from_to_no_match_dst():
    rules = [
        Rule(src=ipset('1.0.0.0/8'), dst=ipset('3.0.0.0/24'), app='app', name='r'),
    ]
    eq_(process.rules_from_to(rules, ipset('1.0.0.0/8'), ipset('2.0.0.0/8')),
        [])


def test_rules_from_to_intersection():
    rules = [
        Rule(src=ipset('0.0.0.0/7'), dst=ipset('2.0.1.0/24'), app='app', name='r'),
    ]
    eq_(process.rules_from_to(rules, ipset('1.0.0.0/8'), ipset('2.0.0.0/8')), [
        Rule(src=ipset('1.0.0.0/8'), dst=ipset('2.0.1.0/24'), app='app', name='r'),
    ])


def test_intersect_rules():
    r1 = [
        Rule(src=ipset('1.0.0.0/24'), dst=ipset('0.0.0.0/0'), app='app', name='r1'),
    ]
    r2 = [
        Rule(src=ipset('1.0.0.10', '1.0.0.14'), dst=ipset('0.0.0.0/0'),
             app='app', name='r2'),
    ]
    r3 = [
        Rule(src=ipset('1.0.0.11', '1.0.0.14'), dst=ipset('0.0.0.0/0'),
             app='app', name='r3'),
    ]
    eq_(process.intersect_rules([r1, r2, r3], ipset('0.0.0.0/0'), ipset('2.0.0.0/8')), [
        Rule(src=ipset('1.0.0.14'), dst=ipset('2.0.0.0/8'), app='app', name='r1+r2+r3'),
    ])
