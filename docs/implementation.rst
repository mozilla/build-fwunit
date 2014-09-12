Implementation Notes
====================

IP Objects
----------

This tool uses `IPy <https://pypi.python.org/pypi/IPy/>`_ to handle IP addresses, ranges, and sets.
However, it extends that functionality to include some additional methods for ``IPSet``\s as well as an ``IPPairs`` class to efficiently represent sets of IP pairs.

All of these classes can be imported from ``fwunit.ip``.

Rules
-----

The output of the processing step is a JSON-formatted object.
The ``rules`` key gives a list of rule objects, each of which has keys

 * ``src`` - a list of source IP ranges
 * ``dst`` - a list of destination IP ranges
 * ``app`` - the name of the permitted application
 * ``name`` - the name of the rule

The rules are normalized as follows (and this is what consumes most of the time in processing):

 * For a given source and destination IP and application, exactly 0 or 1 rules
   match; stated differently, there's no need to consider rules in order.

 * If traffic matches a rule, it is permitted.  If no rule matches, it is denied.
