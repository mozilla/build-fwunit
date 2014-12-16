from fwunit import TestContext
from fwunit.ip import IP, IPSet

rules = TestContext('my-network')

# hosts

servers = IPSet([IP('172.16.1.0/24')])
puppetmaster = IPSet([IP('172.16.1.220')])
adminhost = IPSet([IP('172.16.1.30')])
workers = IPSet([IP('172.16.2.0/24')])

# tests


def test_servers_puppet():
    """The servers can access the puppet master."""
    rules.assertPermits(servers, puppetmaster, 'puppet')

def test_workers_puppet():
    """The workers can access the puppet master."""
    rules.assertPermits(workers, puppetmaster, 'puppet')

def test_workers_ssh():
    """The workers cannot SSH to any server IP."""
    rules.assertDenies(workers, servers, 'ssh')

def test_admin_access():
    """The admin host can access all workers and the puppetmaster via SSH."""
    rules.assertPermits(adminhost, workers + puppetmaster, 'ssh')

def test_vps_access():
    """The sysadmin's VPS can access the admin host"""
    rules.assertPermits('5.5.5.5', adminhost, 'ssh')

