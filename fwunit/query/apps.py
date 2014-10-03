# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .. import tests
from . import base

class AppsQuery(base.Query):

    def __init__(self, subparsers):

        description = """Enumerate the apps allowed between the source and
        destination."""

        subparser = subparsers.add_parser('apps',
                description=description)
        subparser.add_argument('source',
                help="rule source to query against")
        subparser.add_argument('src_ip',
                help="source IP (or network) to query")
        subparser.add_argument('dst_ip',
                help="destination IP (or network) to query")
        super(AppsQuery, self).__init__(subparser)

    def run(self, args, cfg):
        rules = tests.Rules(args.source)
        for app in sorted(rules.allApps(args.src_ip, args.dst_ip)):
            print app
