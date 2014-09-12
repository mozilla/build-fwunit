Processing Policies
===================

The ``fwunit`` command processes a YAML-formatted configuration file describing a
set of "sources" of rule data.  Each top-level key describes a source, and must
have a ``type`` field giving the type of data to be read -- see "Supported
Systems", above.  Each must also have an ``output`` field giving the filename to
write the generated rules to (relative to the configuration file).

The source may optionally have a ``require`` field giving a list of other sources
which should be processed first.

Any additional fields are passed to the policy-type plugin.

.. code-block:: yaml

    aws_releng:
        type: aws
        output: aws_releng.pkl
        dynamic_subnets: [build, test, try, build.servo, bb]
        regions: [us-east-1, us-west-1, us-west-2]

You can pass one or more source names to ``fwunit`` to only process those sources.

Application Maps
----------------

Each policy type comes with its own way of naming applications: strings,
protocol/port numbers, etc.

An "application map" is used to map these type-specific names to common names.
This is invaluable if you are combining policies from multiple types, e.g., AWS
and SRX.

To set this up, add an ``application-map`` key to the source configuration, with
a mapping from type name to common name.  For example:

.. code-block: yaml

    mysource:
        ...
        application-map:
            junos-ssh: ssh
            junos-http: http
            junos-https: https

Note that you *cannot* combine multiple applications into one using an
application map, as this might result in overlapping rules.
