# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import textwrap
import cPickle as pickle
import sys
import argparse
from .parse import Firewall
from .process import policies_to_rules
from fwunit import log


def main():
    description = textwrap.dedent("""\
        Ingest XML ouptput from a Juniper SRX and create a datafile containing
        the procesesd results, ready to run unit tests against.
    """)
    parser = argparse.ArgumentParser(description=description)
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
