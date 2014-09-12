Writing Tests
=============

Flow tests are just like software unit tests: they make assertions about the state of the system under test.
In the case of flow tests, that means asserting that traffic can, or cannot, flow between particular systems.

The functions given here enable such tests.

.. warning::

    The details here may change substantially before fwunit-1.0 is released.

Loading Rules
-------------

Before you can test anything, you'll need to load the rules created with the ``fwunit`` command into memory.
It's safe to do this individually in each test script, as the results are cached.

.. code-block:: python

    from fwunit.tests import Rules

    rules = Rules('/path/to/rules.json')

IPs and IPSets
--------------

The ``IP`` and ``IPSet`` classes come from `IPy <https://pypi.python.org/pypi/IPy/>`_, with minor changes.

The ``IP`` class represents a single IP or CIDR range::

    from fwunit.ip import IP
    server = IP('10.11.12.33')
    subnet = IP('10.11.12.0/23')

When you need to reason about a non-contiguous set of addresses, you need an ``IPSet``.
This is really just a list of ``IP`` instances, but it will remove duplicates, collapse adjacent IPs, and so on. ::

    from fwunit.ip import IP, IPSet
    db_subnets = IPSet([IP('10.11.12.0/23'), IP('10.12.12.0/23')])

In general, tests expeect ``IPSet``\s, but you can pass ``IP`` instances or even bare strings and they will be converted appropriately.

Tests
-----

Once you have the rules loaded, you can start writing test methods::

    internal_network = IPSet([IP('192.168.1.0/24'), IP('192.168.13.0/24')])

    puppetmasters = IPSet([IP(ip) for ip in
        '192.168.13.45',
        '192.168.13.50',
    ])

    def test_puppetmaster_access():
        for app in 'puppet', 'junos-http', 'junos-https':
            fw1.assertPermits(internal_network, puppetmasters, app)

Utility Methods
---------------

The :class:`~fwunit.tests.Rules` class provides a number of useful functions for testing.
Each method logs verbosely, so test failures should have plenty of data for debugging.

.. py:class:: funit.tests.Rules(filename)

    :param filename: file from which to load rules

    .. py:method:: assertDenies(src, dst, app)

        :param src: source IPs
        :param dst: destination IPs
        :param app: application

        Assert that application traffic is denied from any given source IP to any given destination IP.

    .. py:method:: assertPermits(src, dst, app)

        :param src: source IPs
        :param dst: destination IPs
        :param app: application

        Assert that application traffic is allowed from any given source IP to any given destination IP.

    Note that ``assertDenies`` and ``assertPermits`` are not quite opposites:
    if application traffic is allowed between some IP pairs, but denied between others, then both methods will raise ``AssertionError``.

    .. py:method:: sourcesFor(dst, app, ignore_sources=None)

        :param dst: destination IPs
        :param app: application
        :param ignore_sources: source IPs to ignore

        Return an IPSet with all sources for traffic to any IP in dst on
        application app, ignoring flows from ignore_sources.

        This is useful for assertions of the form "access to X is only allowed from Y and Z".

    .. py:method:: allApps(src, dst, debug=False)

        :param src: source IPs
        :param dst: destination IPs
        :param debug: if True, log the full list of matching flows
        
        Return a set of applications with access form src to dst.

        This is useful for verifying that access between two sets of hosts is limited to a short list of applications.

    .. py:method:: appsOn(dst, ignore_sources=None, debug=False)

        :param dst: destination IPs
        :param ignore_sources: source IPs to ignore
        :param debug: if True, log the full list of matching flows

        Return a set of applications with access to dst, ignoring flows from ignore_sources.

        This is useful to verify that there are no unexpected applications allowed on a host.
