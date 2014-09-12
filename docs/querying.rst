Querying
========

Aside from writing unit tests, you can query against a rule source with ``fwunit-query``.

For example:

.. code-block:: none

    fwunit-query enterprise permitted 10.10.1.1 192.168.1.1 ssh
    Flow permitted

See the script's ``--help`` for more detail.
