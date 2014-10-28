# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import bisect
import itertools
from fwunit.ip import IP, IPSet
import logging
from fwunit.types import Rule
from fwunit.common import simplify_rules
from fwunit.common import combine_names
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
    managed_ip_space = IPSet([])
    for id, subnet in aws.get_all_subnets(regions).iteritems():
        name = subnet.tags.get('Name', id)
        dynamic = name in dynamic_subnets or id in dynamic_subnets
        cidr_block = IP(subnet.cidr_block)
        subnet = Subnet(cidr_block=cidr_block, name=name, dynamic=dynamic)
        subnets.append(subnet)
        managed_ip_space = managed_ip_space + IPSet([cidr_block])
    unmanaged_ip_space = IPSet([IP('0.0.0.0/0')]) - managed_ip_space

    logger.info("collecting dynamic subnet IP ranges")
    dynamic_ipsets = {}
    per_host_subnet_ips = IPSet()
    for subnet in subnets:
        if subnet.dynamic:
            ipset = dynamic_ipsets.get(subnet.name, IPSet([]))
            ipset += IPSet([subnet.cidr_block])
            dynamic_ipsets[subnet.name] = ipset
        else:
            per_host_subnet_ips += IPSet([subnet.cidr_block])

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
            if inst_name in sgids_by_instance:
                inst_name = inst_name + ' ({})'.format(instance.id)
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
        assert sg, "no security group with id {}".format(sgid)
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

    rules = {}
    to_intersect = {}
    def make_rules(sgid, local):
        sg = security_groups[sgid]
        for dir, sgrules in [('in', sg.rules), ('out', sg.rules_egress)]:
            for sgrule in sgrules:
                if sgrule.app == '*/any':
                    apps = all_apps | set(['@@other'])
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
                        # first make rules involving non-managed space, leaving
                        # only managed-to-managed
                        if dir == 'in':
                            unmanaged_src = src & unmanaged_ip_space
                            if unmanaged_src:
                                rules.setdefault(app, []).append(Rule(
                                    src=unmanaged_src, dst=dst, app=app, name=name))
                            src = src & managed_ip_space
                        else:
                            unmanaged_dst = dst & unmanaged_ip_space
                            if unmanaged_dst:
                                rules.setdefault(app, []).append(Rule(
                                    src=src, dst=unmanaged_dst, app=app, name=name))
                            dst = dst & managed_ip_space
                        if src and dst:
                            to_intersect.setdefault(app, {}).setdefault(dir, []).append((src, dst, name))

    logger.info("writing rules for dynamic subnets")
    for subnet_name, sgids in sgids_by_dynamic_subnet.iteritems():
        subnet = dynamic_ipsets[subnet_name]
        logger.debug(" subnet %s, %s", subnet_name, subnet)
        for sgid in sgids:
            make_rules(sgid, subnet)

    logger.info("writing rules for instances in per-host subnets")
    per_host_host_ips = IPSet()
    for inst_name, info in sgids_by_instance.iteritems():
        ip, sgids = info
        logger.debug(" instance %s at %s", inst_name, ip)
        host_ip = IPSet([ip])
        per_host_host_ips += host_ip
        for sgid in sgids:
            make_rules(sgid, host_ip)

    logger.info("assuming unrestricted outbound access from unoccupied IPs in per-host subnets")
    unoccupied = per_host_subnet_ips - per_host_host_ips
    for app in all_apps:
        rules.setdefault(app, []).append(Rule(
            src=unoccupied, dst=unmanaged_ip_space, app=app, name='unoccupied/out'))
        to_intersect.setdefault(app, {}).setdefault('out', []).append((unoccupied, managed_ip_space, 'unoccupied/out'))

    # traffic within the manage Ip space is governed both by outbound rules on
    # the source and inbound rules on the destination.
    logger.info("intersecting inbound and outbound rules")
    for app, dirs in to_intersect.iteritems():
        in_rules = dirs.get('in', [])
        out_rules = dirs.get('out', [])
        logger.debug("..for %s", app)
        new_rules = []
        for inr in in_rules:
            for outr in out_rules:
                src = inr[0] & outr[0]
                if not src:
                    continue
                dst = inr[1] & outr[1]
                if not dst:
                    continue
                new_rules.append(Rule(src=src, dst=dst, app=app,
                                      name=combine_names(inr[2], outr[2])))
        # simplify now, within this app, to save space and time
        new_rules = simplify_rules({app: new_rules})[app]
        rules.setdefault(app, []).extend(new_rules)

    rules = simplify_rules(rules)
    return rules
