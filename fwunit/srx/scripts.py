# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .parse import Firewall
from .process import policies_to_rules
from fwunit import common
import logging


def run(cfg, fwunit_cfg):
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    app_map = common.ApplicationMap(cfg)
    firewall = Firewall()
    firewall.parse(cfg)
    return policies_to_rules(app_map, firewall)
