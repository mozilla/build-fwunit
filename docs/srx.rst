Juniper SRX
===========

This source type uses SSH with a username and password to connect to a Juniper SRX firewall.
It only runs 'show' commands, so read-only access is adequate.

Setup
-----

Install fwunit with the ``srx`` tag:

.. code-block:: none

    pip install fwunit[aws]

Add a source to your ``fwunit.yaml`` looking like this:

.. code-block:: yaml

    myfirewall:
        type: srx
        output: myfirewall.pkl
        firewall: fw1.releng.scl3.mozilla.com
        ssh_username: fwunit
        ssh_password: sekr!t

The ``firewall`` config gives a hostname (or IP) of the firewall that accepts SSH connections.
``ssh_username`` and ``ssh_password`` are the credentials for the account.

The process of downloading and processing policies can be very slow, depending on the complexity of your policies.

Assumptions
-----------

This processing makes the following assumptions about your network

  * Rule IPs are limited by the to- and from-zones of the original policy, so
    given a "from any" policy with from-zone ABC, the resulting rule's ``src``
    will be ABC's IP space, not 0.0.0.0/0.  Zone spaces are determined from the
    route table, and thus assume symmetrical forwarding.

  * All directly-connected networks are considered to permit all traffic within
    those networks, on the assumption that the network is an open L2 subnet.

  * Policies allowing application "any" are expanded to include every
    application mentioned in any policy.


