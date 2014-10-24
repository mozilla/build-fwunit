#! /bin/bash

set -e

# nosetests --with-coverage doesn't allow you to specify a coveragerc
coverage erase
coverage run --rcfile=coveragerc --source=fwunit $(which nosetests)
coverage report --rcfile=coveragerc
sphinx-build docs build
