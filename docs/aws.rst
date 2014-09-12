Amazon EC2 Security Groups
==========================

Setup
-----

Install fwunit with the ``aws`` tag:

.. code-block:: none

    pip install fwunit[aws]

Set up your ``~/.boto`` with an account that has access to EC2 and VPC
administrative information.

In your source configuration, include ``dynamic_subnets`` listing the names or
id's of all dynamic subnets (see below).  Also include a ``regions`` field
listing the regions in which you have hosts.

You can include the credentials for an IAM user in the configuration.  If this
is omitted, boto's normal credential search process will apply, including
searching ``~/.boto`` and instance role credentials.

.. code-block:: yaml

    my_aws_stuff:
        type: aws
        output: my_aws_stuff.pkl
        dynamic_subnets: [workers]
        regions: [us-east-1, us-west-1]
        credentials:
            access_key: "ACCESS KEY"
            secret_key: "SECRET KEY"

Security Policy
---------------

The user accessing Amazon should have the following security policy:


.. code-block:: json

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups"
                ],
                "Resource": "*"
            }
        ]
    }

Assumptions
-----------

This processing makes some assumptions about your EC2 layout.  These worked for
us in Mozilla Releng, but may not work for you.

 * Network ACLs are not in use

 * All traffic is contained in subnets in one or more VPCs.

 * Each subnet is either *per-host* or *dynamic*, as described below.

 * All traffic from unoccupied IPs in per-host subnets is implicitly permitted.

 * Subnets with the same name are configured identically.  Such subnets are
   often configured to achieve AZ/region separation.

The Release Engineering AWS environment contains two types of instances, which
always appear in different subnets.  Long-lived instances sit at a single IP
for a long time, acting like traditional servers.  The subnets holding such
instances are considered "per-host" subnets, and the destination IPs for
``fwunit`` rules are determined by examining the IP addresses and security groups
of the instances in the subnets.  All traffic to IPs not assigned to an
instance is implicitly denied.

The instances that perform build, test, and release tasks are transient,
created and destroyed as economics and load warrant.  Subnets containing such
instances are considered "dynamic", and a security group that applies to any
instance in the subnet is assumed to apply to the subnet's entire CIDR block.
This means that these subnets must contain at least one active host.

