# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from . import process


def run(cfg):
    regions = cfg.get('regions', None)
    dynamic_subnets = cfg.get('dynamic_subnets', [])
    return process.get_rules(regions, dynamic_subnets)
