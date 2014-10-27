# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.ip import IP, IPSet

def ipset(*ips):
    """Create an IPSet out of the given strings"""
    return IPSet(map(IP, ips))
