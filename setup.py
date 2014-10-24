# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup, find_packages

import versioneer
versioneer.VCS = 'git'
versioneer.versionfile_source = 'fwunit/_version.py'
versioneer.versionfile_build = 'fwunit/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'fwunit-'

setup(
    name='fwunit',
    description='Unit tests for firewall rules',
    author='Dustin J. Mitchell',
    url='https://github.com/mozilla/build-fwunit',
    author_email='dustin@mozilla.com',
    packages=find_packages(),
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    install_requires=[
        "IPy",
        "nose",
        "blessings",
        "PyYAML",
        "mock",
    ],
    extras_require={
        'srx': [
            "lxml",
            'paramiko',
        ],
        'aws': [
            'boto',
            'moto',
        ],
        'docs': [
            'sphinx',
        ],
    },
    entry_points={
        "console_scripts": [
            'fwunit = fwunit.scripts:main',
            'fwunit-query = fwunit.scripts:query',
        ],
        "fwunit.types": [
            'srx = fwunit.srx.scripts:run [srx]',
            'aws = fwunit.aws.scripts:run [aws]',
            'combine = fwunit.combine.scripts:run',
        ],
    },
    license='MPL2',
)

