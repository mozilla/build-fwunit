fwunit
======

Unit Tests for your Firewall

Feed `fwunit` some data pulled out of your Juniper SRX, let it chew on it for a
while, then run regular old Python unit tests against it.

For example:

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
