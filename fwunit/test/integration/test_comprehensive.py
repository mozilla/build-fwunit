# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import shutil
import sys
import yaml

from fwunit import TestContext
from fwunit import types
from fwunit import scripts
from fwunit.test.util import ipset

FWUNIT_YAML = {
    'rules': {
        'type': 'anything',
        'output': 'rules.json',
    }
}
RULES = {
    'http': [
        # within this ip space
        types.Rule(src=ipset('10.10.0.0/16'), dst=ipset('10.20.0.0/16'), app='http', name='10->10'),
        # from and to "unmanaged" space
        types.Rule(src=ipset('30.10.0.0/16'), dst=ipset('10.20.0.0/16'), app='http', name='30->10'),
        types.Rule(src=ipset('10.10.0.0/16'), dst=ipset('30.20.0.0/16'), app='http', name='10->30'),
        # from and to the 20/8 space
        types.Rule(src=ipset('20.20.0.0/16', '20.30.0.0/16'),
                   dst=ipset('10.20.0.0/16', '10.30.0.0/16'),
                   app='http', name='20->10'),
        types.Rule(src=ipset('10.10.0.0/16', '10.20.0.0/16'),
                   dst=ipset('20.10.0.0/16', '20.20.0.0/16'),
                   app='http', name='10->20'),
    ],
}

old_sys_argv = None
old_cwd = None

def setup():
    global old_sys_argv, old_cwd
    old_sys_argv = sys.argv[:]
    old_cwd = os.getcwd()

    if os.path.exists('test_dir'):
        shutil.rmtree('test_dir')
    os.makedirs('test_dir')
    os.chdir('test_dir')
    yaml.dump(FWUNIT_YAML,
              open('fwunit.yaml', "w"))
    json.dump(dict(rules=types.to_jsonable(RULES)),
              open('rules.json', "w"))


def teardown():
    os.chdir(old_cwd)
    sys.argv = old_sys_argv

    if os.path.exists('test_dir'):
        shutil.rmtree('test_dir')

# run each of the queries once, just to see that the command-line processing,
# rule loading, and analysis connect properly

def test_permitted():
    sys.argv = ['fwunit', 'permitted', 'rules', '10.10.10.1', '10.20.1.1', 'http']
    scripts.query()


def test_denied():
    sys.argv = ['fwunit', 'denied', 'rules', '10.10.10.1', '99.20.1.1', 'http']
    scripts.query()


def test_apps():
    sys.argv = ['fwunit', 'apps', 'rules', '10.10.10.1', '99.20.1.1']
    scripts.query()

# load rules as a test script would

def test_test():
    tc = TestContext('rules')
    tc.assertPermits('10.10.10.1', '10.20.1.1', 'http')
