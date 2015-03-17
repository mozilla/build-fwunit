# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import mock
import re

from nose.tools import eq_
from fwunit.types import Rule
from fwunit.analysis import sources
from fwunit.test.util import ipset
from fwunit import diff

TEN = ipset('10.10.0.0/16')
TEN_0 = ipset('10.10.0.0/17')
TEN_128 = ipset('10.10.128.0/17')
TWENTY = ipset('10.20.0.0/16')
TWENTY_0 = ipset('10.20.0.0/17')
TWENTY_128 = ipset('10.20.128.0/17')

LEFT = {
    'http': [
        Rule(src=ipset('0.0.0.0/0'), dst=ipset('10.20.19.0/24'), app='http', name='web access'),
        Rule(src=ipset('0.0.0.0/0'), dst=ipset('10.20.20.0/25'), app='http', name='stage web access'),
    ],
    'https': [
        Rule(src=ipset('0.0.0.0/0'), dst=ipset('10.20.19.0/24'), app='https', name='https web access'),
    ],
    'db': [
        Rule(src=ipset('10.20.19.0/24'), dst=ipset('10.20.30.15', '10.20.30.19'), app='db', name='db'),
        Rule(src=ipset('10.20.20.0/25'), dst=ipset('10.20.30.16'), app='db', name='stage db'),
    ],
    'ssh': [
        Rule(src=ipset('10.2.1.1'),
                dst=ipset('10.20.19.0/24', '10.20.20.0/25', '10.20.30.15', '10.20.30.16', '10.20.30.19'),
                app='ssh', name='ssh'),
    ]
}
RIGHT = {
    'http': [
        Rule(src=ipset('0.0.0.0/0'), dst=ipset('10.20.19.0/24'), app='http', name='web access'),
        Rule(src=ipset('0.0.0.0/0'), dst=ipset('10.20.20.0/24'), app='http', name='stage web access'),
    ],
    'https': [
        Rule(src=ipset('0.0.0.0/0'), dst=ipset('10.20.19.0/24'), app='https', name='https web access'),
    ],
    'db': [
        Rule(src=ipset('10.20.19.0/24'), dst=ipset('10.20.30.15', '10.20.30.19', '10.20.30.28'),
                app='db', name='db'),
        Rule(src=ipset('10.20.20.0/24'), dst=ipset('10.20.30.16'), app='db', name='stage db'),
    ],
    'ssh': [
        Rule(src=ipset('10.2.1.1'),
                dst=ipset('10.20.20.0/24', '10.20.30.16'),
                app='ssh', name='ssh'),
    ]
}
class FakeSource(sources.Source):

    def __init__(self, rules):
        self.rules = rules


def test_app_diff_add():
    l = []
    r = [Rule(src=TEN, dst=TWENTY, app='http', name='10->20')]
    eq_(list(diff.app_diff('http', l, r)),
        [('+', 'http', TEN, TWENTY)])


def test_app_diff_remove():
    l = [Rule(src=TEN, dst=TWENTY, app='http', name='10->20')]
    r = []
    eq_(list(diff.app_diff('http', l, r)),
        [('-', 'http', TEN, TWENTY)])


def test_app_diff_replace():
    l = [Rule(src=TEN, dst=TWENTY, app='http', name='10->20')]
    r = [Rule(src=TWENTY, dst=TEN, app='http', name='20->10')]
    eq_(list(diff.app_diff('http', l, r)),
        [('-', 'http', TEN, TWENTY),
         ('+', 'http', TWENTY, TEN)])


def test_app_diff_expanded():
    l = [Rule(src=TEN_128, dst=TWENTY, app='http', name='10.128->20')]
    r = [Rule(src=TEN,     dst=TWENTY, app='http', name='10->20')]
    eq_(list(diff.app_diff('http', l, r)),
        [('+', 'http', TEN_0, TWENTY)])


def test_app_diff_expanded_dest():
    l = [Rule(src=TEN, dst=TWENTY_0, app='http', name='10.128->20')]
    r = [Rule(src=TEN, dst=TWENTY,   app='http', name='10->20')]
    eq_(list(diff.app_diff('http', l, r)),
        [('+', 'http', TEN, TWENTY_128)])


def test_app_diff_shrunk():
    l = [Rule(src=TEN,   dst=TWENTY, app='http', name='10->20')]
    r = [Rule(src=TEN_0, dst=TWENTY, app='http', name='10.0/17->20')]
    eq_(list(diff.app_diff('http', l, r)),
        [('-', 'http', TEN_128, TWENTY)])


def test_app_diff_reorg_rules():
    # two different ways to represent the same flows..
    l = [
        Rule(src=TEN_0,   dst=TWENTY_0,   app='http', name='10->20'),
        Rule(src=TEN,     dst=TWENTY_128, app='http', name='10->20'),
    ]
    r = [
        Rule(src=TEN_0,   dst=TWENTY,     app='http', name='10->20'),
        Rule(src=TEN_128, dst=TWENTY_128, app='http', name='10->20'),
    ]
    eq_(list(diff.app_diff('http', l, r)), [])

def test_make_diff():
    eq_(sorted(diff.make_diff(FakeSource(LEFT), FakeSource(RIGHT))), sorted([
        # expand stage from /25 to /24
        ('+', 'db', ipset('10.20.20.128/25'), ipset('10.20.30.16')),
        ('+', 'http', ipset('0.0.0.0/0'), ipset('10.20.20.128/25')),
        ('+', 'ssh', ipset('10.2.1.1'), ipset('10.20.20.128/25')),
        # add production db server
        ('+', 'db', ipset('10.20.19.0/24'), ipset('10.20.30.28')),
        # remove ssh access to production
        ('-', 'ssh', ipset('10.2.1.1'), ipset('10.20.19.0/24', '10.20.30.15', '10.20.30.19')),
    ]))

def test_show_diff():
    with mock.patch('fwunit.analysis.sources.load_source') as load_source, \
         mock.patch('sys.stdout') as stdout:
        def fake_load_source(cfg, name):
            if name == 'left':
                return FakeSource(LEFT)
            else:
                return FakeSource(RIGHT)
        load_source.side_effect = fake_load_source
        written = []
        def fake_write(data):
            written.append(data)
        stdout.write.side_effect = fake_write
        diff.show_diff(None, 'left', 'right')
        written = ''.join(written)
        # rather than assert on exactly what's written, which may change as presentaiton improves,
        # just assert that we wrote lines starting with + or -, after stripping escape codes
        for line in filter(None, written.split('\n')):
            line = re.sub('\x1b[^m]+m', '', line)
            assert line.startswith('+') or line.startswith('-'), line
