# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import paramiko

def show(cfg, request):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(cfg['firewall'], username=cfg['ssh_username'], password=cfg['ssh_password'])
    stdin, stdout, stderr = ssh.exec_command('show %s | display xml | no-more\n' % request,
                                             timeout=240.0)
    return stdout.read()
