Unit Tests for your Network
===========================

Any developer worth their salt tests their software.  The benefits are many:

 * Exercise the code

 * Reduce ambiguity by stating the desired behaviors twice (in the
   implementation, in the tests, and maybe even a third time in the
   documentation)

 * Enable code refactoring without changing expected behavior

With `fwunit`, you can do the same for security policies on your network.

Principle of Operation
----------------------

Testing policies is a two-part operation: first fetch and process the data from
all of the applicable devices, constructing a set of *rules*.  Then run the
tests against the rules.

This package handles the first part entirely, and provides a set of utility
functions you can use in your tests.  You can write tests using whatever Python
testing framework you like.  We recommend [nose](http://nose.readthedocs.org/).

Supported Policy Types
======================

`fwunit` can read policies from:

 * [`srx`] Juniper SRXes, using manually downloaded XML files
 * [`aws`] Amazon EC2 security groups and VPC subnets

Installation
============

To install, set up a [Python virtualenv](https://virtualenv.pypa.io/) and then run

    pip install fwunit[srx,aws]

where the bit in brackets lists the systems you'd like to process, from the section above.

Processing Policies
===================

The `fwunit` command processes a YAML-formatted configuration file describing a
set of "sources" of rule data.  Each top-level key describes a source, and must
have a `type` field giving the type of data to be read -- see "Supported
Systems", above.  Each must also have an `output` field giving the filename to
write the generated rules to (relative to the configuration file).

The source may optionally have a `require` field giving a list of other sources
which should be processed first.

Any additional fields are passed to the policy-type plugin.

Example:

```
fw1_releng:
    type: srx
    output: fw1_releng.pkl
    security-policies-xml: fw1_releng_scl3_show_security_policies.xml
    route-xml: fw1_releng_scl3_show_route.xml
    configuration-security-zones-xml: fw1_releng_scl3_show_configuration_security_zones.xml

aws_releng:
    type: aws
    output: aws_releng.pkl
    dynamic_subnets: [build, test, try, build.servo, bb]
    regions: [us-east-1, us-west-1, us-west-2]
```

You can pass one or more source names to `fwunit` to only process those sources.

Application Maps
----------------

Each policy type comes with its own way of naming applications: strings,
protocol/port numbers, etc.

An "application map" is used to map these type-specific names to common names.
This is invaluable if you are combining policies from multiple types, e.g., AWS
and SRX.

To set this up, add an `application-map` key to the source configuration, with
a mapping from type name to common name.  For example:

```
mysource:
    ...
    application-map:
        junos-ssh: ssh
        junos-http: http
        junos-https: https
```

Note that you *cannot* combine multiple applications into one using an
application map, as this might result in overlapping rules.

Juniper SRX
-----------

First, download the relevant XML from your firewall:

    fw1> show route | display xml | save route.xml
    fw1> show security policies | display xml | save security_policies.xml
    fw1> show configuration security zones | display xml | save configuration_security_zones.xml

and then copy those `.xml` files somewhere local using scp.  Configure them in your source:

```
myfirewall:
    type: srx
    output: myfirewall.pkl
    security-policies-xml: fw1_releng_scl3_show_security_policies.xml
    route-xml: fw1_releng_scl3_show_route.xml
    configuration-security-zones-xml: fw1_releng_scl3_show_configuration_security_zones.xml
```

and run `fwunit`.

This process may take a while, depending on the complexity of your policies.

### Assumptions ###

This processing makes the following assumpotions about your network

  * Rule IPs are limited by the to- and from-zones of the original policy, so
    given a "from any" policy with from-zone ABC, the resulting rule's `src`
    will be ABC's IP space, not 0.0.0.0/0.  Zone spaces are determined from the
    route table, and thus assume symmetrical forwarding.

  * All directly-connected networks are considered to permit all traffic within
    those networks, on the assumption that the network is an open L2 subnet.

  * Policies allowing application "any" are expanded to include every
    application mentioned in any policy.

Amazon EC2 Security Groups
--------------------------

Set up your `~/.boto` with an account that has access to EC2 and VPC
administrative information.

In your source configuration, include `dynamic_subnets` listing the names or
id's of all dynamic subnets (see below).  Also include a `regions` field
listing the regions in which you have hosts.

Example:
```
my_aws_stuff:
    type: aws
    output: my_aws_stuff.pkl
    dynamic_subnets: [workers]
    regions: [us-east-1, us-west-1]
```

### Assumptions ###

This processing makes some assumptions about your EC2 layout.  These worked for
us in Mozilla Releng, but may not work for you.

 * Network ACLs are not in use

 * All traffic is contained in subnets in one or more VPCs.

 * Each subnet is either *per-host* or *dynamic*, as described below.

 * Outbound rules are not used.

 * Inbound rules are always specified with an IP-based source, not another security group.

 * Subnets with the same name are configured identically.  Such subnets are
   often configured to achieve AZ/region separation.

The Release Engineering AWS environment contains two types of instances, which
always appear in different subnets.  Long-lived instances sit at a single IP
for a long time, acting like traditional servers.  The subnets holding such
instances are considered "per-host" subnets, and the destination IPs for
`fwunit` rules are determined by examining the IP addresses and security groups
of the instances in the subnets.  All traffic to IPs not assigned to an
instance is implicitly denied.

The instances that perform build, test, and release tasks are transient,
created and destroyed as economics and load warrant.  Subnets containing such
instances are considered "dynamic", and a security group that applies to any
instance in the subnet is assumed to apply to the subnet's entire CIDR block.
This means that 

Writing Tests
=============

*To Be Written* - see tests.py for now.  Example:

```python
from fwunit.ip import IP, IPSet
from fwunit.tests import Rules

fw1 = Rules('rules.pkl')

internal_network = IPSet([IP('192.168.1.0/24'), IP('192.168.13.0/24')])

puppetmasters = IPSet([IP(ip) for ip in
    '192.168.13.45',
    '192.168.13.50',
])

def test_puppetmaster_access():
    for app in 'puppet', 'junos-http', 'junos-https':
        fw1.assertPermits(internal_network, puppetmasters, app)
```

IP Objects
----------

This tool uses [IPy](https://pypi.python.org/pypi/IPy/) to handle IP addresses,
ranges, and sets.  However, it extends that functionality to include some
additional methods for `IPSet`\s as well as an `IPPairs` class to efficiently
represent sets of IP pairs.

All of these classes can be imported from ``fwunit.ip``.

Rules
=====

The output of the processing step is a pickled list of Rule objects.

A Rule has `src` and `dst` attributes, IPSets consisting of the source and
destination addresses to which it applies, and `app`, the name of the traffic
type allowed.  It also has a `name` attribute indicating where it came from
(e.g., the SRX policy name).

The rules are normalized as follows (and this is what consumes most of the time in processing):

  * For a given source and destination IP and application, exactly 0 or 1 rules
    match; stated differently, there's no need to consider rules in order.

  * If traffic matches a rule, it is permitted.  If no rule matches, it is denied.
