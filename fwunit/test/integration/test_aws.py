# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from nose.tools import eq_
import logging
import moto
import boto.vpc
from fwunit.ip import IP, IPSet
from fwunit import common
from fwunit.types import Rule
from fwunit.aws import aws
from fwunit.aws import process

mock = moto.mock_ec2()

SECURITY_GROUPS = [
    ('admin_ssh', [
        dict(ip_protocol='tcp', from_port=22,
             to_port=22, cidr_ip='192.168.10.0/24'),
    ]),
    ('webapp', [
        dict(ip_protocol='tcp', from_port=80,
             to_port=81, cidr_ip='0.0.0.0/0'),
    ]),
]
NETWORK = [
    # moto can currently only handle one region; see
    # https://github.com/spulec/moto/issues/27
    # https://github.com/spulec/moto/pull/242
    # https://github.com/spulec/moto/pull/243
    ('us-east-1', [
        ('vpc1', '172.16.0.0/16', [
            ('perhost', '172.16.1.0/24', [
                ('web1', '172.16.1.1', ['admin_ssh', 'webapp']),
                ('web2', '172.16.1.2', ['admin_ssh', 'webapp']),
            ]),
            ('dynamic', '172.16.2.0/24', [
                ('dynhost', '172.16.2.17', ['admin_ssh']),
                ('dynhost', '172.16.2.20', ['admin_ssh']),
            ]),
            ('perhost', '172.16.3.0/24', [
                ('server4', '172.16.3.1', ['admin_ssh']),
            ]),
        ]),
    ]),
]

RULES = {
    'ssh': [
        Rule(src=IPSet([IP('172.16.1.0/24'), IP('172.16.3.0/24')]) - IPSet([IP('172.16.1.1'), IP('172.16.1.2'), IP('172.16.3.1')]),
             dst=IPSet([IP('0.0.0.0/0')]) - IPSet([IP('172.16.1.0/24'), IP('172.16.2.0/24'), IP('172.16.3.0/24')]),
             app='ssh', name='unoccupied/out'),
        Rule(src=IPSet([IP('192.168.10.0/24')]),
             dst=IPSet([IP('172.16.1.1'), IP('172.16.1.2'), IP('172.16.2.0/24'), IP('172.16.3.1')]),
             app='ssh', name='admin_ssh/in'),
    ],
    'web': [
        Rule(src=IPSet([IP('172.16.1.0/24'), IP('172.16.3.0/24')]) - IPSet([IP('172.16.1.1'), IP('172.16.1.2'), IP('172.16.3.1')]),
             dst=IPSet([IP('0.0.0.0/0')]) - IPSet([IP('172.16.1.0/24'), IP('172.16.2.0/24'), IP('172.16.3.0/24')])
                 + IPSet([IP('172.16.1.1'), IP('172.16.1.2')]),
             app='web', name='unoccupied/out+webapp/in'),
        Rule(src=IPSet([IP('0.0.0.0/0')]) - IPSet([IP('172.16.1.0/24'), IP('172.16.2.0/24'), IP('172.16.3.0/24')]),
             dst=IPSet([IP('172.16.1.1'), IP('172.16.1.2')]),
             app='web', name='webapp/in'),
    ],
}


def setup_module():
    mock.start()
    l = logging.getLogger('mock_network')

    # create the network
    for region, vpcs in NETWORK:
        conn = boto.vpc.connect_to_region(region)
        l.info("Setting up region {}".format(region))

        sgids_by_name = {}
        for name, kwargses in SECURITY_GROUPS:
            sg = conn.create_security_group(name, 'd:{}'.format(name))
            sgids_by_name[name] = sg.id
            l.info("Security group {} has id {}".format(name, sg.id))
            for kwargs in kwargses:
                conn.authorize_security_group(name, **kwargs)

        for name, vpc_cidr, subnets in vpcs:
            vpc_cidr_ip = IP(vpc_cidr)
            vpc = conn.create_vpc(vpc_cidr)
            vpc.add_tag('Name', name)
            l.info("VPC {} has id {}".format(name, vpc.id))
            for name, subnet_cidr, instances in subnets:
                subnet_cidr_ip = IP(subnet_cidr)
                assert subnet_cidr_ip in vpc_cidr_ip
                subnet = conn.create_subnet(vpc.id, subnet_cidr)
                subnet.add_tag('Name', name)
                l.info("Subnet {} has id {}".format(name, subnet.id))
                for name, address, sgs in instances:
                    address_ip = IP(address)
                    assert address_ip in subnet_cidr_ip
                    sgids = [sgids_by_name[sg] for sg in sgs]
                    res = conn.run_instances(
                        'ami', security_group_ids=sgids, subnet_id=subnet.id,
                        private_ip_address=address)
                    inst = res.instances[0]
                    inst.add_tag('Name', name)
                    l.info("Instance {} has id {} in subnet {} with security groups {}".format(
                        name, inst.id, subnet.id, ', '.join(sgids)))


def teardown_module():
    mock.stop()


def test_aws():
    aws_conn = aws.AWS()
    regions = ['us-east-1', 'us-west-2']
    dynamic_subnets = ['dynamic']
    app_map = common.ApplicationMap({
        'application-map': {
            '22/tcp': 'ssh',
            '80-81/tcp': 'web',
        },
    })

    eq_(process.get_rules(aws_conn, app_map, regions, dynamic_subnets), RULES)
