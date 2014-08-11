# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .parse import Firewall
from .process import policies_to_rules
from fwunit import common


def run(cfg, fwunit_cfg):
    app_map = common.ApplicationMap(cfg)
    firewall = Firewall(
        security_policies_xml=open(cfg['security-policies-xml']),
        route_xml=open(cfg['route-xml']),
        configuration_security_zones_xml=open(cfg['configuration-security-zones-xml']))
    return policies_to_rules(app_map, firewall)
