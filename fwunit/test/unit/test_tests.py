# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import tempfile
import shutil
import yaml
import json
import os
from fwunit.test.util import ipset
from fwunit.tests import Rules
from fwunit.test.util.test_rules import TEST_RULES
from fwunit import types
from nose.tools import eq_

dir = None
old_cwd = None
rules = None

def setup_module():
    global dir, old_cwd, rules
    dir = tempfile.mkdtemp()
    old_cwd = os.getcwd()
    os.chdir(dir)
    open('fwunit.yaml', 'w').write(yaml.dump({
        'test_source': {
            'output': os.path.join(dir, 'test_source.json'),
        },
    }))
    json.dump({'rules': types.to_jsonable(TEST_RULES)},
              open('test_source.json', 'w'))
    rules = Rules('test_source')

def teardown_module():
    global old_cwd
    os.chdir(old_cwd)
    shutil.rmtree(dir)

def test_assertDenies():
    rules.assertDenies('10.1.1.1', '10.1.0.0', 'ping')

def test_assertDenies_from_other():
    rules.assertDenies('10.1.1.1', '10.1.0.0', 'someotherapp')

def test_assertPermits():
    rules.assertPermits('99.1.1.1', '10.1.0.0', 'ping')

def test_assertPermits_from_other():
    rules.assertPermits('1.2.3.4', '10.1.0.0', 'someotherapp')

def test_sourcesFor():
    eq_(rules.sourcesFor('10.1.1.1', 'ssh'), ipset('10.0.0.0/8'))

def test_sourcesFor_unknown_app():
    eq_(rules.sourcesFor('10.1.1.1', 'somerandomapp'), ipset('1.2.3.4'))

def test_allApps():
    eq_(rules.allApps('10.0.0.0/8', '10.0.9.2'), set(['ssh', 'puppet']))

def test_allApps_other():
    eq_(rules.allApps('1.2.3.4/32', '10.0.9.2'), set(['any']))

def test_assertAllApps():
    rules.assertAllApps('10.0.0.0/8', '10.0.9.2', set(['ssh', 'puppet']))

