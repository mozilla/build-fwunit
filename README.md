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

Supported Systems
=================

`fwunit` can read data from:

 * [`srx`] Juniper SRXes, using manually downloaded XML files

Installation
============

To install, set up a [Python virtualenv](https://virtualenv.pypa.io/) and then run

    pip install fwunit[srx,aws]

where the bit in brackets lists the systems you'd like to process, from the section above.

Processing Policies
===================

Juniper SRX
-----------

First, download the relevant XML from your firewall:

    fw1> show route | display xml | save route.xml
    fw1> show security policies | display xml | save security_policies.xml
    fw1> show configuration security zones | display xml | save configuration_security_zones.xml

and then copy those `.xml` files somewhere local using scp, and run
`fwunit-srx` against them:

    $ fwunit-srx \
        --route-xml=route.xml \
        --security-policies-xml=security_policies.xml \
        --configuration-security-zones-xml=configuration_security_zones.xml \
        --output=rules.pkl

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
administrative information.  Then run

    $ fwunit-aws --output=rules.pkl

Adding `--dynamic-subnet NAME_OR_ID` for each dynamic subnet (see below) in
your configuration.

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
