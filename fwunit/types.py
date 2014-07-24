# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# special types that are used within the Pickle file

from collections import namedtuple

# A rule is a simple derivative of a policy:
# - always 'permit'
# - only one app
# - specifies ipsets for source and destinations
# - makes no reference to zones
Rule = namedtuple('Rule', ['src', 'dst', 'app', 'name'])
