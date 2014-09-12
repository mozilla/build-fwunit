Writing Tests
=============

*To Be Written* - see tests.py for now.  Example:

.. code-block:: python

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
