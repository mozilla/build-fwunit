# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import cPickle as pickle
import argparse
import logging
import sys
import textwrap
import yaml
import os
import os.path
from fwunit import log
import pkg_resources

logger = logging.getLogger(__name__)


def main():
    description = textwrap.dedent("""Process security policies into fwunit rules""")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--config', '-c',
        help="YAML configuration file", dest='config_file', type=str, default='fwunit.yaml')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--boto-verbose', action='store_true',
                        help="Enable VERY verbose logging from boto (if in use)")
    parser.add_argument('sources', nargs='*', help="sources to generate (default: ALL)")

    args = parser.parse_args(sys.argv[1:])

    log.setup(args.verbose)
    if not args.boto_verbose:
        logging.getLogger('boto').setLevel(logging.CRITICAL)

    cfg = yaml.load(open(args.config_file))

    # chdir to cfg file so rel paths work
    config_dir = os.path.dirname(os.path.abspath(args.config_file))
    os.chdir(config_dir)

    requested_sources = args.sources
    if not requested_sources or requested_sources == ['ALL']:
        requested_sources = cfg.keys()
    for source in requested_sources:
        if source not in cfg:
            parser.error("no such source '{}'".format(source))

    entry_points = {ep.name: ep for ep in pkg_resources.iter_entry_points('fwunit.types')}

    # sort all of the sources in dependency order
    requirements = {}
    for source in cfg:
        requirements[source] = cfg[source].get('require', [])

    ordered_sources = []
    def require(source):
        if source in ordered_sources:
            return
        for req in requirements[source]:
            print "{} req {}".format(source, req)
            if req not in cfg:
                parser.error("unknown requirement '{}'".format(source))
            require(req)
        ordered_sources.append(source)
    for source in requirements.iterkeys():
        require(source)

    for source in ordered_sources:
        if source not in requested_sources:
            continue
        src_cfg = cfg[source]
        if 'type' not in src_cfg:
            parser.error("source '{}' has no type".format(source))
        typ = src_cfg['type']
        if typ not in entry_points:
            parser.error("source '{}' has undefined type {}".format(source, typ))
        ep = entry_points[typ].load()

        if 'output' not in src_cfg:
            parser.error("source '{}' has no output".format(source))
        output = src_cfg['output']

        logger.warning("running %s", source)
        rules = ep(src_cfg)
        logger.warning("writing resulting rules to %s", output)
        pickle.dump(rules, open(output, "w"))
