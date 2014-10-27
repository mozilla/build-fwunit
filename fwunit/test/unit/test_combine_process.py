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


def test_one_address_space():
    rules = {'app': [
        Rule(ipset('1.2.3.4'), ipset('1.7.7.7'), 'app', 'p2p'),
        Rule(ipset('1.2.5.0/24'), ipset('1.7.7.7'), 'app', 'net'),
    ]}
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=rules)))
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
    with no_simplify():
        result = process.combine(dict(
            ord=dict(ip_space=['0.0.0.0/2'], rules=ord_rules),
            lga=dict(ip_space=['64.0.0.0/2'], rules=lga_rules)))
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
    nyc_rules = {'app': [
        Rule(ipset('1.2.5.0/24'), ipset('2.2.5.0/24'), 'app', 'nyc'),
    ]}
    dca_rules = {'app': [
        Rule(ipset('2.7.7.0/24'), ipset('1.7.7.0/24'), 'app', 'dca'),
    ]}
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(result, {})


def test_identical_rules():
    rules = {'app': [
        Rule(ipset('2.7.7.0/24'), ipset('1.7.7.0/24'), 'app', 'nyc-dca'),
    ]}
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=rules)))
        eq_(result, rules)


def test_overlapping_rules():
    nyc_rules = {'app': [
        Rule(ipset('1.1.0.0/16'), ipset('2.0.0.0/8'), 'app', 'nyc'),
    ]}
    dca_rules = {'app': [
        Rule(ipset('1.0.0.0/8'), ipset('2.1.0.0/16'), 'app', 'dca'),
    ]}
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(result, {'app': [
            # takes the intersection of both rules:
            Rule(ipset('1.1.0.0/16'), ipset('2.1.0.0/16'), 'app', 'dca+nyc'),
        ]})


def test_limited_by_space():
    ord_rules = {'app': [
    ]}
    nyc_rules = {'app': [
        # /7 covers both ord and nyc
        Rule(ipset('0.0.0.0/7'), ipset('2.0.0.0/8'), 'app', 'nyc'),
    ]}
    dca_rules = {'app': [
        Rule(ipset('0.0.0.0/7'), ipset('2.0.0.0/8'), 'app', 'dca'),
    ]}
    with no_simplify():
        result = process.combine(
            dict(ord=dict(ip_space=['0.0.0.0/8'], rules=ord_rules),
                 nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(result, {'app': [
            # only nyc's address space is allowed
            Rule(ipset('1.0.0.0/8'), ipset('2.0.0.0/8'), 'app', 'dca+nyc'),
        ]})


def test_multiple_matches():
    nyc_rules = {'app': [
        Rule(ipset('1.1.1.1'), ipset('2.0.0.0/8'), 'app', 'one'),
        Rule(ipset('1.1.1.2'), ipset('2.0.0.0/8'), 'app', 'two'),
        Rule(ipset('1.1.1.3'), ipset('2.0.0.0/8'), 'app', 'three'),
    ]}
    dca_rules = {'app': [
        Rule(ipset('1.0.0.0/8'), ipset('2.7.8.8'), 'app', 'eight'),
        Rule(ipset('1.0.0.0/8'), ipset('2.7.8.9'), 'app', 'nine'),
    ]}
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(sorted(result['app']), sorted([
            # takes the intersection of all rules:
            Rule(src=ipset('1.1.1.1'), dst=ipset('2.7.8.8'), app='app', name='eight+one'),
            Rule(src=ipset('1.1.1.1'), dst=ipset('2.7.8.9'), app='app', name='nine+one'),
            Rule(src=ipset('1.1.1.2'), dst=ipset('2.7.8.8'), app='app', name='eight+two'),
            Rule(src=ipset('1.1.1.2'), dst=ipset('2.7.8.9'), app='app', name='nine+two'),
            Rule(src=ipset('1.1.1.3'), dst=ipset('2.7.8.8'), app='app', name='eight+three'),
            Rule(src=ipset('1.1.1.3'), dst=ipset('2.7.8.9'), app='app', name='nine+three')
        ]))
