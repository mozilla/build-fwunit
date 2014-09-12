Principle of Operation
======================

Testing policies is a two-part operation: first fetch and process the data from
all of the applicable devices, constructing a set of *rules*.  Then run the
tests against the rules.

This package handles the first part entirely, and provides a set of utility
functions you can use in your tests.  You can write tests using whatever Python
testing framework you like.  We recommend `nose <http://nose.readthedocs.org/>`_.
