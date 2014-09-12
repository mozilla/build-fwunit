Policy Combiner
===============

A large organization will have multiple policy sources, perhaps in different
regions or of different types.  Before you can write tests and reason about the
overall flows, these must be combined into a single rule set.

In most cases, each policy source has a set of IP addresses for which it is
responsible for controlling access.  It controls both incoming and outgoing
traffic in this space, but does not see traffic between addresses *not* in this
space.

To combine policy sources, create a ``combine`` source, requiring the sources it
combines.  Give the IP space for each source, and specify an output file:

.. code-block:: yaml

    enterprise:
        type: combine
        require: [dca, nyc, ord]
        address_spaces:
            dca: [10.10.0.0/16, 10.15.0.0/14]
            ord: 192.168.0.0/24
            nyc: 172.16.1.0/24

Assumptions
-----------

* Traffic is only filtered at the source and destination

* Any traffic beteween IPs not in any defined address space is forbidden (more
  likely, such traffic is not interesting)


