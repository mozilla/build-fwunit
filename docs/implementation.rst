Implementation Notes
====================

IP Objects
----------

This tool uses `IPy <https://pypi.python.org/pypi/IPy/>`_ to handle IP addresses, ranges, and sets.
However, it extends that functionality to include some additional methods for ``IPSet``\s as well as an ``IPPairs`` class to efficiently represent sets of IP pairs.

All of these classes can be imported directly from ``fwunit``.

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

 * Policies allowing any application are represented by explicit rules for each known application, with the addition of rules with application '@@other' to represent the unknown applications.


Loading Source Objects
----------------------

Rule sets are embedded in :py:class:`~fwunit.analysis.sources.Source` objects, which provide a set of useful methods for analysis.
In a testing environment, rule sets are loaded via :py:class:`~fwunit.analysis.testcontext.TestContext`; this section describes access to rules within fwunit itself.

To get a source object, you will first need a config, which can be retrieved from :py:func:`~fwunit.analysis.config.load_config`:

.. py:function:: fwunit.analysis.config.load_config(filename="fwunit.yaml")

    :param filename: the configuration filename to load
    :returns: a config object

    Load a configuration file.
    As a side-effect, this function chdir's to the configuration directory.

    The function operates on the assumption that a single process will only ever reference one configuration, and thus caches the configuration after the first call.
    Subsequent calls with the same filename will return the same object.
    Subsequent calls with a different filename will raise an exception.

With the config object in hand, call :py:func:`~fwunit.analysis.sources.load_source`:

.. py:function:: fwunit.analysis.sources.load_source(config, source)

    :param config: a config object
    :param source: the name of the source to load
    :returns: a source object
    :rtype: :py:class:`~fwunit.analysis.sources.Source`

    Load the ruleset for the given source.
    Rulesets are cached globally to the process.

Using Source Objects
--------------------

.. py:class:: fwunit.analysis.sources.Source

    The data from a particular source in ``fwunit.yaml``, along with some analysis methods.

    .. py:method:: rulesDeny(src, dst, apps)

        :param src: source IPs
        :param dst: destination IPs
        :param apps: application names
        :type apps: list or string

        Returns True if the rules deny all traffic from *src* to *dst* via all given *apps*; otherwise False.

    .. py:method:: rulesPermit(src, dst, apps)

        :param src: source IPs
        :param dst: destination IPs
        :param apps: application names
        :type apps: list or string

        Returns True if the rules allow all traffic from *src* to *dst* via all given *apps*; otherwise False.

    Note that ``rulesdeny(..)`` is not the same as ``not rulesPermit(..)``: if some -- but not all -- traffic is permitted from *src* to *dst*, then both methods will return False.

    .. py:method:: allApps(src, dst, debug=False)

        :param src: source IPs
        :param dst: destination IPs
        :param debug: if True, log the full list of matching flows
        
        See :py:meth:`~fwunit.analysis.testcontext.TestContext.allApps`.

    .. py:method:: sourcesFor(dst, app, ignore_sources=None)

        :param dst: destination IPs
        :param app: application
        :param ignore_sources: source IPs to ignore

        See :py:meth:`~fwunit.analysis.testcontext.TestContext.sourcesFor`.
