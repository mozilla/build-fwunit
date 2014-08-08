# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import boto.ec2
import boto.vpc
from repoze.lru import lru_cache


@lru_cache(10)
def get_ec2_connection(region):
    return boto.ec2.connect_to_region(region)


@lru_cache(10)
def get_vpc_connection(region):
    conn = get_ec2_connection(region)
    return boto.vpc.VPCConnection(region=conn.region)


def all_regions():
    regions = boto.ec2.regions()
    return [r.name for r in regions]
