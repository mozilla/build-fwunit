# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from nose.tools import assert_raises
import contextlib
import copy
import mock
from fwunit.combine import scripts
from fwunit.test.util import ipset

base_cfg = {
    'fw.ord': {'output': 'fw.ord.json'},
    'fw.lax': {'output': 'fw.lax.json'},
    'fw.nyc': {'output': 'fw.nyc.json'},
    'enterprise': {
        'address_spaces': {
            'ord': '100.0.0.0/8',
            'lax': '200.0.0.0/8',
            'nyc': '240.0.0.0/8',
        },
        'routes': {
        },
    },
}

exp_address_spaces = {
    'ord': ipset('100.0.0.0/8'),
    'lax': ipset('200.0.0.0/8'),
    'nyc': ipset('240.0.0.0/8'),
    'unmanaged': ipset('0.0.0.0/0')
        - ipset('100.0.0.0/8') - ipset('200.0.0.0/8') - ipset('240.0.0.0/8'),
}

empty_exp_routes = {
    (s, d): set()
    for s in exp_address_spaces
    for d in exp_address_spaces
}

def exp_sources(*srcs):
    return {s: "rules for " + s for s in srcs}


@contextlib.contextmanager
def patched_combine():
    with mock.patch('fwunit.combine.scripts.get_rules') as get_rules:
        get_rules.side_effect = lambda cfg, n: 'rules for ' + n
        with mock.patch('fwunit.combine.process.combine') as combine:
            yield combine


def test_run_one_route():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['routes']['ord -> lax'] = ['fw1.ord']
    exp_routes = empty_exp_routes.copy()
    exp_routes['ord', 'lax'] = set(['fw1.ord'])
    with patched_combine() as combine:
        scripts.run(cfg['enterprise'], cfg)
        combine.assert_called_with(exp_address_spaces, exp_routes, exp_sources('fw1.ord'))


def test_run_address_space_list():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['address_spaces']['ord'] = ['100.0.0.0/9', '100.128.0.0/9']
    with patched_combine() as combine:
        scripts.run(cfg['enterprise'], cfg)
        combine.assert_called_with(exp_address_spaces, empty_exp_routes, exp_sources())


def test_run_route_sources_not_list():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['routes']['ord -> lax'] = 'fw1.ord'
    exp_routes = empty_exp_routes.copy()
    exp_routes['ord', 'lax'] = set(['fw1.ord'])
    with patched_combine() as combine:
        scripts.run(cfg['enterprise'], cfg)
        combine.assert_called_with(exp_address_spaces, exp_routes, exp_sources('fw1.ord'))


def test_run_route_with_invalid_space():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['routes']['mdw -> lax'] = 'fw1.ord'
    with patched_combine():
        assert_raises(RuntimeError, lambda:
            scripts.run(cfg['enterprise'], cfg))


def test_run_star_source():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['routes']['* -> lax'] = 'fw1.lax'
    exp_routes = empty_exp_routes.copy()
    exp_routes['ord', 'lax'] = set(['fw1.lax'])
    exp_routes['lax', 'lax'] = set(['fw1.lax'])
    exp_routes['nyc', 'lax'] = set(['fw1.lax'])
    exp_routes['unmanaged', 'lax'] = set(['fw1.lax'])
    with patched_combine() as combine:
        scripts.run(cfg['enterprise'], cfg)
        combine.assert_called_with(exp_address_spaces, exp_routes, exp_sources('fw1.lax'))


def test_run_star_dest():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['routes']['lax -> *'] = 'fw1.lax'
    exp_routes = empty_exp_routes.copy()
    exp_routes['lax', 'ord'] = set(['fw1.lax'])
    exp_routes['lax', 'nyc'] = set(['fw1.lax'])
    exp_routes['lax', 'lax'] = set(['fw1.lax'])
    exp_routes['lax', 'unmanaged'] = set(['fw1.lax'])
    with patched_combine() as combine:
        scripts.run(cfg['enterprise'], cfg)
        combine.assert_called_with(exp_address_spaces, exp_routes, exp_sources('fw1.lax'))


def test_run_bidirectional():
    cfg = copy.deepcopy(base_cfg)
    cfg['enterprise']['routes']['lax <-> *'] = 'fw1.lax'
    exp_routes = empty_exp_routes.copy()
    exp_routes['ord', 'lax'] = set(['fw1.lax'])
    exp_routes['lax', 'lax'] = set(['fw1.lax'])
    exp_routes['nyc', 'lax'] = set(['fw1.lax'])
    exp_routes['unmanaged', 'lax'] = set(['fw1.lax'])
    exp_routes['lax', 'ord'] = set(['fw1.lax'])
    exp_routes['lax', 'nyc'] = set(['fw1.lax'])
    exp_routes['lax', 'lax'] = set(['fw1.lax'])
    exp_routes['lax', 'unmanaged'] = set(['fw1.lax'])
    with patched_combine() as combine:
        scripts.run(cfg['enterprise'], cfg)
        combine.assert_called_with(exp_address_spaces, exp_routes, exp_sources('fw1.lax'))
