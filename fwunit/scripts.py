# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import cPickle as Pickle
import sys
import argparse
from fwunit.parse import Firewall
from fwunit.process import policies_to_rules


def prep():
    epilog = """
        Provide the following:
            --security-policies-xml: output of 'show security policies | display xml'
            --route-xml: output of 'show route | display xml'
            --configuration-security-zones-xml: output of 'show configuration security zones | display xml'
        The output will be written to --output, defaulting to 'rules.pkl'
    """
    parser = argparse.ArgumentParser(
        description='Ingest output from a Juniper firewall and create a datafile containing the results.', epilog=epilog)
    parser.add_argument(
        '--security-policies-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--route-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--configuration-security-zones-xml', type=argparse.FileType('r'), required=True)
    parser.add_argument(
        '--output', dest='output_file', type=str, default='rules.pkl')

    args = parser.parse_args(sys.argv[1:])

    firewall = Firewall(
        security_policies_xml=args.security_policies_xml,
        route_xml=args.route_xml,
        configuration_security_zones_xml=args.configuration_security_zones_xml)
    rules = policies_to_rules(firewall)
    Pickle.dump(rules, open(args.output_file, "w"))

