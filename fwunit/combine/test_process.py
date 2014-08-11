# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.types import Rule
from fwunit.ip import IP, IPSet
from fwunit.combine import process
from fwunit.common import simplify_rules
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


def s(*ips):
    return IPSet([IP(ip) for ip in ips])


def test_one_address_space():
    rules = [
        Rule(s('1.2.3.4'), s('1.7.7.7'), 'app', 'p2p'),
        Rule(s('1.2.5.0/24'), s('1.7.7.7'), 'app', 'net'),
    ]
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=rules)))
        eq_(sorted(result), sorted(rules))


def test_nonoverlapping_rules():
    nyc_rules = [
        Rule(s('1.2.5.0/24'), s('2.2.5.0/24'), 'app', 'nyc'),
    ]
    dca_rules = [
        Rule(s('2.7.7.0/24'), s('1.7.7.0/24'), 'app', 'dca'),
    ]
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(result, [])


def test_identical_rules():
    rules = [
        Rule(s('2.7.7.0/24'), s('1.7.7.0/24'), 'app', 'nyc-dca'),
    ]
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=rules)))
        eq_(result, rules)


def test_overlapping_rules():
    nyc_rules = [
        Rule(s('1.1.0.0/16'), s('2.0.0.0/8'), 'app', 'nyc'),
    ]
    dca_rules = [
        Rule(s('1.0.0.0/8'), s('2.1.0.0/16'), 'app', 'dca'),
    ]
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(result, [
            # takes the intersection of both rules:
            Rule(s('1.1.0.0/16'), s('2.1.0.0/16'), 'app', 'dca+nyc'),
        ])


def test_limited_by_space():
    ord_rules = [
    ]
    nyc_rules = [
        # /7 covers both ord and nyc
        Rule(s('0.0.0.0/7'), s('2.0.0.0/8'), 'app', 'nyc'),
    ]
    dca_rules = [
        Rule(s('0.0.0.0/7'), s('2.0.0.0/8'), 'app', 'dca'),
    ]
    with no_simplify():
        result = process.combine(
            dict(ord=dict(ip_space=['0.0.0.0/8'], rules=ord_rules),
                 nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(sorted(result), sorted([
            # only nyc's address space is allowed
            Rule(s('1.0.0.0/8'), s('2.0.0.0/8'), 'app', 'dca+nyc'),
        ]))


def test_multiple_matches():
    nyc_rules = [
        Rule(s('1.1.1.1'), s('2.0.0.0/8'), 'app', 'one'),
        Rule(s('1.1.1.2'), s('2.0.0.0/8'), 'app', 'two'),
        Rule(s('1.1.1.3'), s('2.0.0.0/8'), 'app', 'three'),
    ]
    dca_rules = [
        Rule(s('1.0.0.0/8'), s('2.7.8.8'), 'app', 'eight'),
        Rule(s('1.0.0.0/8'), s('2.7.8.9'), 'app', 'nine'),
    ]
    with no_simplify():
        result = process.combine(
            dict(nyc=dict(ip_space=['1.0.0.0/8'], rules=nyc_rules),
                 dca=dict(ip_space=['2.0.0.0/8'], rules=dca_rules)))
        eq_(sorted(result), sorted([
            # takes the intersection of all rules:
            Rule(src=IPSet([IP('1.1.1.1')]), dst=IPSet([IP('2.7.8.8')]), app='app', name='eight+one'),
            Rule(src=IPSet([IP('1.1.1.1')]), dst=IPSet([IP('2.7.8.9')]), app='app', name='nine+one'),
            Rule(src=IPSet([IP('1.1.1.2')]), dst=IPSet([IP('2.7.8.8')]), app='app', name='eight+two'),
            Rule(src=IPSet([IP('1.1.1.2')]), dst=IPSet([IP('2.7.8.9')]), app='app', name='nine+two'),
            Rule(src=IPSet([IP('1.1.1.3')]), dst=IPSet([IP('2.7.8.8')]), app='app', name='eight+three'),
            Rule(src=IPSet([IP('1.1.1.3')]), dst=IPSet([IP('2.7.8.9')]), app='app', name='nine+three')
        ]))
