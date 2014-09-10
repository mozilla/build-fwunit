# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import paramiko

class Connection(object):

    def __init__(self, cfg):
        self.cfg = cfg
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.cfg['firewall'],
                         username=self.cfg['ssh_username'],
                         password=self.cfg['ssh_password'])

    def show(self, request):
        stdin, stdout, stderr = self.ssh.exec_command(
                'show %s | display xml | no-more\n' % request,
                timeout=240.0)
        return stdout.read()
