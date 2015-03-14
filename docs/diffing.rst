Diffing
=======

Two compare two rulesets, use ``fwunit-diff``.
For example:

.. code-block:: none

    $ fwunit-diff yesterday.json my-network
    + ssh IPSet([IP('172.16.3.0/24')]) -> IPSet([IP('10.90.110.0/23')])

The two sources for comparison can be the names of sources defined in ``fwunit.yaml``, or filenames (e.g., to backup copies).
