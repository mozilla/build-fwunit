# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import boto.ec2
import boto.vpc
import logging
from repoze.lru import lru_cache

logger = logging.getLogger(__name__)


@lru_cache(10)
def get_ec2_connection(region):
    return boto.ec2.connect_to_region(region)


@lru_cache(10)
def get_vpc_connection(region):
    conn = get_ec2_connection(region)
    return boto.vpc.VPCConnection(region=conn.region)


@lru_cache(1)
def all_regions():
    regions = boto.ec2.regions()
    return [r.name for r in regions]


def get_all_subnets(regions):
    all_subnets = {}
    for region in regions:
        logger.debug("fetching subnets in %s" % region)
        conn = get_vpc_connection(region)
        for subnet in conn.get_all_subnets():
            all_subnets[subnet.id] = subnet
    return all_subnets


def get_all_instances(regions):
    all_instances = {}
    for region in regions:
        logger.debug("fetching instances in %s" % region)
        conn = get_ec2_connection(region)
        for instance in conn.get_only_instances():
            all_instances[instance.id] = instance
    return all_instances

@lru_cache(1000)
def get_security_group(sgid):
    conn = get_ec2_connection(sgid.region)
    logger.debug("fetching security group %s in %s", sgid.id, sgid.region)
    sgs = conn.get_all_security_groups(group_ids=[sgid.id])
    if not sgs:
        return None
    sg = sgs[0]
    # verify it doesn't have outbound rules
    msg = "fwunit assumes outbound rules are unrestricted (the default)"
    assert len(sg.rules_egress) == 1, msg
    assert sg.rules_egress[0].ip_protocol == "-1", msg
    assert sg.rules_egress[0].from_port == None, msg
    assert sg.rules_egress[0].to_port == None, msg
    return sg
