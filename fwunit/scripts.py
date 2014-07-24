# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import textwrap
import cPickle as pickle
import sys
import argparse
from fwunit.parse import Firewall
from fwunit.process import policies_to_rules
from fwunit import log


def prep():
    description = textwrap.dedent("""\
        Ingest XML ouptput from a Juniper firewall and create a datafile containing the procesesd results,
        ready to run unit tests against.
    """)

    epilog = textwrap.dedent("""\
        COMMON USAGE

            1. Download the relevant XML from your firewall, e.g.,

                fw1> show route | display xml | save route.xml

            and then copy `route.xml` somewhere local using scp.  See below for the full list of files.

            2. Run `fwunit-prep`:

                $ fwunit-prep --route-xml=route.xml [...] --output=fw1.pkl

            3. Write unit tests using the methods in fwunit.tests:

                # fw1_tests.py
                from fwunit.tests import load_rules
                from fwunit.ip import IP, IPSet

                fw1 = load_rules('fw1.pkl')

                def test_sometihng():
                    fw1.assertDenies(..)
            
            4. Run the tests with your favorite test-runner:

                $ nosetests fw1_tests.py

        INPUTS

        The inputs are:

            --security-policies-xml: output of 'show security policies | display xml'
            --route-xml: output of 'show route | display xml'
            --configuration-security-zones-xml: output of 'show configuration security zones | display xml'

        The output will be written to --output, defaulting to 'rules.pkl'

        OUTPUT FORMAT

        The output contains a list of Rule objects, where each Rule has `src`
        and `dst`, IPSets consisting of the source and destination addresses to
        which it applies; `app`, the name of the Juniper application to which
        it applies, and `name`, the name of the juniper policy from which it
        was derived.

        The rules are normalized as follows:

         - for a given source and destination IP and application, exactly 0 or 1 rules match;
           stated differently, the in-order processing of policies is already "baked in"

         - flow IPs are limited by the to- and from-zones of the original policy, so given a "from any"
           policy with from-zone ABC, the resulting rule's `src` will be ABC's IP space, not 0.0.0.0/0.

         - application "all" is translated into every application that appears anywhere in the config.

    """)
    parser = argparse.ArgumentParser(description=description, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--security-policies-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--route-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--configuration-security-zones-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--output', dest='output_file', type=str, default='rules.pkl')
    parser.add_argument( '--verbose', action='store_true')

    args = parser.parse_args(sys.argv[1:])

    log.setup(args.verbose)

    firewall = Firewall(
        security_policies_xml=args.security_policies_xml,
        route_xml=args.route_xml,
        configuration_security_zones_xml=args.configuration_security_zones_xml)
    rules = policies_to_rules(firewall)
    pickle.dump(rules, open(args.output_file, "w"))
