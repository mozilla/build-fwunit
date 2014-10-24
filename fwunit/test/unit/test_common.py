# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.ip import IP, IPSet
from fwunit.types import Rule
from nose.tools import eq_
from fwunit.common import simplify_rules

def _ipset(ip):
    if isinstance(ip, basestring):
        ip = IP(ip)
    if isinstance(ip, IP):
        ip = IPSet([ip])
    return ip


def r(src, dst, app='testapp', name='n'):
    return Rule(src=_ipset(src), dst=_ipset(dst), app=app, name=name)


def test_simplify_empty():
    """Simplifying an empty set results in an empty set"""
    eq_(simplify_rules({}), {})


def test_simplify_no_combine():
    """With no common sources or destinations, nothing changes"""
    rules = {'testapp': [
        r('10.0.0.0', '20.0.0.0'), 
        r('20.0.0.0', '30.0.0.0'), 
        r('30.0.0.0', '40.0.0.0'),
    ]}
    eq_(simplify_rules(rules), rules)


def test_simplify_combine():
    """Rules with the same source are combined"""
    rules = {'testapp': [
        r('10.0.0.0', '20.0.0.0'), 
        r('20.0.0.0', '30.0.0.0'), 
        r('10.0.0.0', '40.0.0.0'),
    ]}
    exp = {'testapp': [
        r('10.0.0.0', IPSet([IP('20.0.0.0'), IP('40.0.0.0')])),
        r('20.0.0.0', '30.0.0.0'), 
    ]}
    eq_(simplify_rules(rules), exp)


def test_simplify_combine_iterations():
    """A set of rules that requires a few passes to simplify is fully simplified"""
    rules = {'testapp': [
        r('10.0.0.0', IPSet([IP('20.0.0.0')])),
        r('10.0.0.0', IPSet([IP('30.0.0.0')])),
        r('11.0.0.0', IPSet([IP('20.0.0.0'), IP('30.0.0.0')])),
        r('12.0.0.0', IPSet([IP('20.0.0.0'), IP('30.0.0.0')])),
        r(IPSet([IP('10.0.0.0'), IP('11.0.0.0'), IP('12.0.0.0')]),
          IPSet([IP('30.0.0.0'), IP('40.0.0.0')])),
    ]}
    exp = {'testapp': [
        r(IPSet([IP('10.0.0.0'), IP('11.0.0.0'), IP('12.0.0.0')]),
          IPSet([IP('20.0.0.0'), IP('30.0.0.0'), IP('40.0.0.0')])),
    ]}
    eq_(simplify_rules(rules), exp)
