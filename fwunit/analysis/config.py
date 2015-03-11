# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import yaml

_loaded_config = None

def load_config(filename="fwunit.yaml"):
    """Load the config, which is stored persistently for the duration of the
    process.  As a side-effect, this chdir's to the configuration directory.
    This function can be called multiple times with the same configuration
    filename."""
    global _loaded_config
    if _loaded_config:
        if _loaded_config[0] != filename:
            raise RuntimeError("load_config already called with %r" % (_loaded_config[0],))
        return

    # chdir to cfg file so rel paths work
    config_dir = os.path.dirname(os.path.abspath(filename))
    os.chdir(config_dir)

    _loaded_config = (filename, yaml.load(open(filename)))
    return _loaded_config[1]
