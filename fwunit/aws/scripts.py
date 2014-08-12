# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from . import process
from . import aws
from fwunit import common


def run(cfg, fwunit_cfg):
    app_map = common.ApplicationMap(cfg)
    regions = cfg.get('regions', None)
    dynamic_subnets = cfg.get('dynamic_subnets', [])
    if 'credentials' in cfg:
        aws_conn = aws.AWS(cfg['credentials']['access_key'],
                           cfg['credentials']['secret_key'])
    else:
        aws_conn = aws.AWS()
    return process.get_rules(aws_conn, app_map, regions, dynamic_subnets)
