#! /bin/bash

set -e

nosetests --with-coverage --cover-package=fwunit --cover-inclusive --cover-min-percentage=46
sphinx-build docs build
