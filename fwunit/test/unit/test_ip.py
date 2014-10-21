# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.ip import IP, IPSet, IPPairs
from nose.tools import assert_false
from nose.tools import assert_true
from nose.tools import eq_


def test_ipset_isdisjoint():
    a = IP('128.0.0.0/16')
    b = IP('129.0.0.0/16')
    c = IP('130.0.0.0/16')
    assert_true(IPSet([a, b]).isdisjoint(IPSet([c])))
    assert_false(IPSet([a, b]).isdisjoint(IPSet([b, c])))
    assert_false(IPSet([a]).isdisjoint(IPSet([a, b])))
    assert_false(IPSet([a]).isdisjoint(IPSet([a, c])))
    assert_false(IPSet([a, b]).isdisjoint(IPSet([b, c])))

    assert_true(IPSet([IP('0.0.0.0/1')])
                .isdisjoint(IPSet([IP('128.0.0.0/1')])))
    assert_false(IPSet([IP('0.0.0.0/1')]).isdisjoint(IPSet([IP('0.0.0.0/2')])))
    assert_false(IPSet([IP('0.0.0.0/2')]).isdisjoint(IPSet([IP('0.0.0.0/1')])))
    assert_false(IPSet([IP('0.0.0.0/2')]).isdisjoint(IPSet([IP('0.1.2.3')])))
    assert_false(IPSet([IP('0.1.2.3')]).isdisjoint(IPSet([IP('0.0.0.0/2')])))
    assert_true(IPSet([IP('1.1.1.1'), IP('1.1.1.3')])
            .isdisjoint(IPSet([IP('1.1.1.2'), IP('1.1.1.4')])))
    assert_false(IPSet([
        IP('1.1.1.1'),
        IP('1.1.1.3'),
        IP('1.1.2.0/24'),
    ]).isdisjoint(IPSet([
        IP('1.1.2.2'),
        IP('1.1.1.4'),
    ])))


def test_ipset_and_single_ip():
    eq_(ten24s & IPSet([IP('10.0.1.10')]), IPSet([IP('10.0.1.10')]))

ten24s = IPSet([
    IP('10.0.1.0/24'),
    IP('10.0.3.0/24'),
    IP('10.0.5.0/24'),
    IP('10.0.7.0/24'),
])


def test_ipset_and_ip_list():
    eq_(ten24s & IPSet([
        IP('10.0.0.99'),
        IP('10.0.1.10'),
        IP('10.0.3.40'),
        IP('11.1.1.99'),
    ]), IPSet([
        IP('10.0.1.10'),
        IP('10.0.3.40'),
    ]))


def test_ipset_and_larger_net():
    eq_(ten24s & IPSet([IP('10.0.0.0/22')]),
        IPSet([IP('10.0.1.0/24'), IP('10.0.3.0/24')]))

def test_ippairs():
    any = IPSet([IP('0.0.0.0/0')])
    ten = IPSet([IP('10.0.0.0/8')])
    not_ten = any - ten
    ten26 = IPSet([IP('10.26.0.0/16')])
    not_ten26 = any - ten26
    ten33 = IPSet([IP('10.33.0.0/16')])
    eq_(IPPairs((any, any)) - IPPairs((any, ten)),
        IPPairs((any, not_ten)))
    eq_(IPPairs((any, any)) - IPPairs((any, ten)) - IPPairs((any, ten26)),
        IPPairs((any, not_ten)))
    eq_(IPPairs((any, any)) - IPPairs((any, ten)) - IPPairs((ten26, any)),
        IPPairs((not_ten26, not_ten)))
    eq_(IPPairs((any, ten26 + ten33)) - IPPairs((any, ten)),
        IPPairs())
    eq_(IPPairs((ten, ten)) - IPPairs((ten26, ten26)),
        IPPairs((ten, ten - ten26), (ten - ten26, ten26)))
        # TODO: equivalent to, but doesn't compare equal to:
        #  IPPairs((ten - ten26, ten), (ten26, ten - ten26)))
