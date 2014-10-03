# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
from .. import tests
from . import base
from blessings import Terminal

class DeniedQuery(base.Query):

    def __init__(self, subparsers):

        description = """Check for a matching rule; exits successfully if the
        flow is denied, and unsuccessfully if it is permitted.  For queries
        between networks, if *any* flow between the given networks is
        permitted, the query is unsuccessful."""

        subparser = subparsers.add_parser('denied',
                description=description)
        subparser.add_argument('source',
                help="rule source to query against")
        subparser.add_argument('src_ip',
                help="source IP (or network) to query")
        subparser.add_argument('dst_ip',
                help="destination IP (or network) to query")
        subparser.add_argument('app',
                help="application to query")
        super(DeniedQuery, self).__init__(subparser)

    def run(self, args, cfg):
        terminal = Terminal()
        rules = tests.Rules(args.source)
        try:
            rules.assertDenies(args.src_ip, args.dst_ip, args.app)
        except AssertionError:
            if not args.quiet:
                print terminal.black_on_red("Flow not denied")
            sys.exit(1)
        else:
            if not args.quiet:
                print terminal.black_on_green("Flow denied")

