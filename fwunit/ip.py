# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import IPy
import bisect

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

    # see https://github.com/haypo/python-ipy/pull/25
    def __contains__(self, ip):
        valid_masks = self.prefixtable.keys()
        if isinstance(ip, IP):
            #Don't dig through more-specific ranges
            ip_mask = ip._prefixlen
            valid_masks = [x for x in valid_masks if x <= ip_mask]
        for mask in sorted(valid_masks):
            i = bisect.bisect(self.prefixtable[mask], ip)
            # Because of sorting order, a match can only occur in the prefix
            # that comes before the result of the search.
            if i and ip in self.prefixtable[mask][i - 1]:
                return True

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

    def __lt__(self, other):
        return self.prefixes < other.prefixes


class IPPairs(object):
    """Reasonably compact representation of a set of source-destination pairs,
    with the ability to do some basic arithmetic."""

    def __init__(self, *pairs):
        self._pairs = list(pairs)
        self._optimize()

    def __iter__(self):
        return self._pairs.__iter__()

    def __eq__(self, other):
        # TODO: this can show equal IPPairs that have been constructed
        # differently as different.  It's good enough for tests.
        return self._pairs == other._pairs

    def __repr__(self):
        return 'IPPairs(*[\n%s\n])' % ('\n'.join("  " + 
           '%r\n   -> %r' % p for p in self._pairs))

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

    def _optimize(self):
        if len(self._pairs) < 2:
            return
        while True:
            changed = False
            for reverse in 1, 0:  # finish with non-reversed
                self._pairs.sort(key=(lambda p: tuple(reversed(p)) if reverse else None))
                i = len(self._pairs) - 2
                while i >= 0:
                    if self._pairs[i][reverse] == self._pairs[i+1][reverse]:
                        if reverse:
                            self._pairs[i] = (self._pairs[i][0] + self._pairs[i+1][0], self._pairs[i][1])
                        else:
                            self._pairs[i] = (self._pairs[i][0], self._pairs[i][1] + self._pairs[i+1][1])
                        del self._pairs[i+1]
                        changed = True
                    i -= 1
            if not changed:
                break

    def __nonzero__(self):
        return len(self._pairs) != 0

