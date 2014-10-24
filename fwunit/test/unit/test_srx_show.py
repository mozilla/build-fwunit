# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from fwunit.srx import show
from nose.tools import eq_
import mock
from cStringIO import StringIO

@mock.patch('paramiko.SSHClient')
def test_show_ok(SSHClient):
    xml = '<rpc-reply>\n</rpc-reply>'
    SSHClient().exec_command.return_value = StringIO(), StringIO(xml), StringIO()

    cfg = dict(firewall = 'fw', ssh_username = 'uu', ssh_password = 'pp')
    eq_(show.Connection(cfg).show('route'), xml)

    SSHClient().set_missing_host_key_policy.assert_called_with(mock.ANY)
    SSHClient().connect.assert_called_with('fw', username='uu', password='pp')
    SSHClient().exec_command.assert_called_with('show route | display xml | no-more\n', timeout=240.0)
