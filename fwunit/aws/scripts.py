# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import cPickle as pickle
import argparse
import logging
import sys
import textwrap
from fwunit import log
from . import process

logger = logging.getLogger(__name__)


def main():
    description = textwrap.dedent("""\
        Process AWS security groups and VPC configuration into a set of fwunit
        rules.
    """)
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        '--output', dest='output_file', type=str, default='rules.pkl')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--dynamic-subnet', '-d',
                        help='add a subnet, by id or name to the list of "dynamic" subnets',
                        dest='dynamic_subnets', action='append',
                        default=[])
    parser.add_argument('--region', '-r',
                        help='add a region to examine (default is all)',
                        dest='regions', action='append')
    parser.add_argument('--boto-verbose', action='store_true',
                        help="Enable VERY verbose logging from boto")

    args = parser.parse_args(sys.argv[1:])

    log.setup(args.verbose)
    if not args.boto_verbose:
        logging.getLogger('boto').setLevel(logging.CRITICAL)

    rules = process.get_rules(args.regions, args.dynamic_subnets)
    pickle.dump(rules, open(args.output_file, "w"))
