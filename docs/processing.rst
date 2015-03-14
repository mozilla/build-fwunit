Processing Policies
===================

To gather data about your network flows, you will need to define one or more "sources" in a configuration file.
Each source describes a set of flow configurations for fwunit to convert into its internal representation and store.
For example, you might define one source for each distinct firewall in your organization, or for each distinct AWS account.

You'll then run ``fwunit`` in the directory containing the configuration file, and it will process the policies from each source and write them to disk, ready for analysis.

You can pass one or more source names to ``fwunit`` to only process those sources.
Otherwise it processes all sources, ordered by their dependencies.

Configuration File
------------------

The ``fwunit`` command processes a YAML-formatted configuration file describing a set of "sources" of rule data.
Each top-level key describes a source, and must have a ``type`` field giving the type of data to be read -- see "Supported Systems", above.

.. code-block:: yaml

    aws_releng:
        type: aws
        output: aws_releng.json
        dynamic_subnets: [build, test, try, build.servo, bb]
        regions: [us-east-1, us-west-1, us-west-2]

Each must also have an ``output`` field giving the filename to write the generated rules to (relative to the configuration file).

The source may optionally have a ``require`` field giving a list of other sources which should be processed first.

Any additional fields are passed to the policy-type plugin.
See the documentation of those plugins for more information.

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
