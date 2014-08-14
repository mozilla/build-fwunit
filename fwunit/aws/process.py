# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import bisect
import itertools
from fwunit.ip import IP, IPSet
import logging
from fwunit.types import Rule
from fwunit.common import simplify_rules
from collections import namedtuple

logger = logging.getLogger(__name__)

Subnet = namedtuple('Subnet', ['cidr_block', 'name', 'dynamic'])
SecurityGroupId = namedtuple('SecurityGroupId', ['id', 'region'])


def get_rules(aws, app_map, regions, dynamic_subnets):
    if not regions:
        logger.info("Getting all regions")
        regions = aws.all_regions()

    logger.info("collecting subnets")
    subnets = []
    for id, subnet in aws.get_all_subnets(regions).iteritems():
        name = subnet.tags.get('Name', id)
        dynamic = name in dynamic_subnets or id in dynamic_subnets
        subnet = Subnet(
            cidr_block=IP(subnet.cidr_block), name=name, dynamic=dynamic)
        subnets.append(subnet)

    logger.info("collecting dynamic subnet IP ranges")
    dynamic_ipsets = {}
    for subnet in subnets:
        if subnet.dynamic:
            ipset = dynamic_ipsets.get(subnet.name, IPSet([]))
            ipset += IPSet([subnet.cidr_block])
            dynamic_ipsets[subnet.name] = ipset

    # sort by IP subnet, so we can use a binary search
    logger.info("sorting subnets by IP")
    subnets.sort(key=lambda s: s.cidr_block)
    _subnet_blocks = [s.cidr_block for s in subnets]

    def subnet_by_ip(ip):
        i = bisect.bisect_right(_subnet_blocks, ip)
        if i and ip in _subnet_blocks[i - 1]:
            return subnets[i - 1]

    logger.info("examining instances")
    sgids_by_dynamic_subnet = {}  # {subnet name: set of SecurityGroupIds}
    sgids_by_instance = {}  # {instance_name: [ip, set of SecurityGroupIds]}
    all_sgids = set()
    ips_by_sg = {}  # {group id: IPSet}
    for id, instance in aws.get_all_instances(regions).iteritems():
        if instance.state == 'terminated' or instance.state == 'shutting-down':
            continue  # meh, who cares
        if not instance.vpc_id:
            continue  # not in vpc; ignored
        if not instance.private_ip_address:
            logger.debug(
                "ignoring instance with no private_ip_address: %s, tags %r",
                instance.id, instance.tags)
            continue
        ip = IP(instance.private_ip_address)

        for g in instance.groups:
            ips_by_sg[g.id] = ips_by_sg.get(g.id, IPSet([])) + IPSet([IP(ip)])

        subnet = subnet_by_ip(ip)
        if not subnet:
            logger.debug(
                "ignoring instance with no matching subnet for %s: %s, tags %r",
                ip, instance.id, instance.tags)
            continue

        if subnet.dynamic:
            sgset = sgids_by_dynamic_subnet.setdefault(subnet.name, set())
        else:
            inst_name = instance.tags.get('Name', instance.id)
            sgset = set()
            sgids_by_instance[inst_name] = [ip, sgset]
        new_sgids = set(SecurityGroupId(g.id, instance.region.name)
                        for g in instance.groups)
        sgset.update(new_sgids)
        all_sgids.update(new_sgids)

    logger.info("accumulating security groups")
    all_apps = set(app_map.values())
    security_groups = {}
    for sgid in all_sgids:
        sg = security_groups[sgid] = aws.get_security_group(sgid)
        # pre-process all of the rules' apps now
        for sgrule in itertools.chain(sg.rules, sg.rules_egress):
            proto = str(sgrule.ip_protocol)
            if proto == '-1':
                proto = 'any'
            if sgrule.from_port == sgrule.to_port:
                if str(sgrule.from_port) in ("None", "-1"):
                    app = "*/{}".format(proto)
                else:
                    app = '{}/{}'.format(sgrule.from_port, proto)
            else:
                app = '{}-{}/{}'.format(sgrule.from_port, sgrule.to_port, proto)
            app = app_map[app]
            sgrule.app = app
            all_apps.add(app)

    rules = []

    def make_rules(sgid, local):
        sg = security_groups[sgid]
        if not sg:
            logger.warning(
                "No such security group %s in %s", sgid.sgid, sgid.region)
            return
        for dir, sgrules in [('in', sg.rules), ('out', sg.rules_egress)]:
            for sgrule in sgrules:
                if sgrule.app == '*/any':
                    apps = all_apps
                else:
                    apps = [sgrule.app]
                for app in apps:
                    for grant in sgrule.grants:
                        if grant.cidr_ip:
                            remote = IPSet([IP(grant.cidr_ip)])
                        else:
                            remote = ips_by_sg.get(grant.group_id, None)
                            if not remote:
                                continue
                        src, dst = (remote, local) if dir == 'in' else (local, remote)
                        name = "{}/{}".format(sg.name, dir)
                        rules.append(Rule(src=src, dst=dst, app=app, name=name))

    logger.info("writing rules for dynamic subnets")
    for subnet_name, sgids in sgids_by_dynamic_subnet.iteritems():
        subnet = dynamic_ipsets[subnet_name]
        logger.debug(" subnet %s, %s", subnet_name, subnet)
        for sgid in sgids:
            make_rules(sgid, subnet)

    logger.info("writing rules for instance in per-host subnets")
    for inst_name, info in sgids_by_instance.iteritems():
        ip, sgids = info
        logger.debug(" instance %s at %s", inst_name, ip)
        host_ip = IPSet([ip])
        for sgid in sgids:
            make_rules(sgid, host_ip)

    rules = simplify_rules(rules)
    return rules
