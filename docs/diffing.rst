Diffing
=======

Two compare two rulesets, use ``fwunit-diff``.
For example:

.. code-block:: none

    $ fwunit-diff yesterday today
    + ssh IPSet([IP('172.16.3.0/24')]) -> IPSet([IP('10.90.110.0/23')])
