from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

# import the user-facing interface
from fwunit.analysis.testcontext import TestContext

# create a "fake" fwunit.tests.Rules
class tests(object):

    Rules = TestContext

import sys
sys.modules['fwunit.tests'] = tests
del sys
