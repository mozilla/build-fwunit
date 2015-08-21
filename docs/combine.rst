Policy Combiner
===============

A large organization will have multiple policy sources, perhaps in different
regions or of different types.  Before you can write tests and reason about the
overall flows, these must be combined into a single rule set.

A complicating factor is that, depending on how flows are routed between
particular address spaces, they may flow through an arbitrary set of firewalls.
For example, traffic from San Francisco to New York may flow through the
Colorado and Chicago firewalls, while traffic from Iowa city only flows through
the Chicago firewall.

To accomplish this, the policy combiner requires you to separate IP addresses
into "address spaces", then define the sources defining the rules between these
spaces.

For example:

.. code-block:: yaml

    enterprise:
        type: combine
        require: [fw.dca, fw.lax, fw.ord]
        address_spaces:
            dca: [10.10.0.0/16, 10.15.0.0/14]
            ord: 192.168.0.0/24
            lax: 172.16.2.0/24
        routes:
            # all traffic to or from dca passes through its firewall
            'dca <-> *': fw.dca
            # similarly for the other sites
            'ord <-> *': fw.ord
            'lax <-> *': fw.lax
            # traffic from dca to lax passes through ord too, but not the
            # reverse
            'dca -> lax': fw.ord
            # and all external traffic is via lax (and ord for dca)
            'dca <-> unmanaged': [fw1.ord, fw1.lax]
            'ord <-> unmanaged': fw1.lax

If (as in this example) the address spaces do not cover the entirety of IPv4, then an address space named ``unmanaged`` is automatically created to cover the remainder.

The ``routes`` mapping defines the set of firewalls between pairs of IP spaces.  The ``*`` wildcard matches all address spaces (including ``unmanaged``).
The ``<->`` symbol is equivalent to listing two routes, one in each direction.

Assumptions
-----------

* Any traffic beteween IPs not in any defined address space is forbidden (more
  likely, such traffic is not interesting)


