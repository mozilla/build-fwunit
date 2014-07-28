# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import IPy

# IPy's IP seems sufficient
IP = IPy.IP


class IPSet(IPy.IPSet):
    # IPy's IPSet needs some help

    def isdisjoint(self, other):
        left = iter(self.prefixes)
        right = iter(other.prefixes)
        try:
            l = left.next()
            r = right.next()
            while True:
                if l in r or r in l:
                    return False
                if l < r:
                    l = left.next()
                else:
                    r = right.next()
        except StopIteration:
            return True

    def __and__(self, other):
        left = iter(self.prefixes)
        right = iter(other.prefixes)
        result = []
        try:
            l = left.next()
            r = right.next()
            while True:
                if l in r:
                    result.append(l)
                    l = left.next()
                    continue
                elif r in l:
                    result.append(r)
                    r = right.next()
                    continue
                if l < r:
                    l = left.next()
                else:
                    r = right.next()
        except StopIteration:
            return IPSet(result)

    # override to create instances of the correct class
    def __add__(self, other):
        return IPSet(self.prefixes + other.prefixes)

    # override to create instances of the correct class
    def __sub__(self, other):
        new = IPSet(self.prefixes)
        for prefix in other:
            new.discard(prefix)
        return new

    def __eq__(self, other):
        return self.prefixes == other.prefixes


class IPPairs(object):

    """
    Reasonably compact representation of a set of source-destination pairs,
    with the ability to do some basic arithmetic.
    """

    def __init__(self, *pairs):
        self._pairs = sorted(pairs)

    def __iter__(self):
        return self._pairs.__iter__()

    def __eq__(self, other):
        # this isn't quite right, as there are several ways to describe
        # a particular set of IP pairs as sets of IPSets
        return self._pairs == other._pairs

    def __repr__(self):
        return 'IPPairs(*[\n%s\n])' % ('\n'.join("  " + `p` for p in self._pairs))

    def __sub__(self, other):
        new_pairs = []
        empty = lambda pair: len(pair[0]) == 0 or len(pair[1]) == 0
        for sa, da in self._pairs:
            for sb, db in other._pairs:
                # eliminate non-overlap
                if sa.isdisjoint(sb) or da.isdisjoint(db):
                    new_pairs.append((sa, da))
                    continue
                for pair in (sa & sb, da - db), (sa - sb, da - db), (sa - sb, da & db):
                    if not empty(pair):
                        new_pairs.append(pair)
        return IPPairs(*new_pairs)

    def __nonzero__(self):
        return len(self._pairs) != 0

    @classmethod
    def test(cls):
        any = IPSet([IP('0.0.0.0/0')])
        ten = IPSet([IP('10.0.0.0/8')])
        ten26 = IPSet([IP('10.26.0.0/16')])
        ten33 = IPSet([IP('10.33.0.0/16')])
        print IPPairs((any, any)) - IPPairs((any, ten))
        print IPPairs((any, any)) - IPPairs((any, ten)) - IPPairs((any, ten26))
        print IPPairs((any, any)) - IPPairs((any, ten)) - IPPairs((ten26, any))
        print IPPairs((any, ten26 + ten33)) - IPPairs((any, ten))

if __name__ == "__main__":
    # simple unit tests for .isdisjoint
    assert IPSet([IP('0.0.0.0/1')]).isdisjoint(IPSet([IP('128.0.0.0/1')]))
    assert not IPSet([IP('0.0.0.0/1')]).isdisjoint(IPSet([IP('0.0.0.0/2')]))
    assert not IPSet([IP('0.0.0.0/2')]).isdisjoint(IPSet([IP('0.0.0.0/1')]))
    assert not IPSet([IP('0.0.0.0/2')]).isdisjoint(IPSet([IP('0.1.2.3')]))
    assert not IPSet([IP('0.1.2.3')]).isdisjoint(IPSet([IP('0.0.0.0/2')]))
    assert IPSet([IP('1.1.1.1'), IP('1.1.1.3')]).isdisjoint(
        IPSet([IP('1.1.1.2'), IP('1.1.1.4')]))
    assert not IPSet([IP('1.1.1.1'), IP('1.1.1.3'), IP(
        '1.1.2.0/24')]).isdisjoint(IPSet([IP('1.1.2.2'), IP('1.1.1.4')]))

    # IPSet doesn't support ==, so testing __and__ is difficult
