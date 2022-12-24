# Sigma configuration discovery
# Copyright 2016-2018 Thomas Patzke, Florian Roth

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from collections import Iterable
from pathlib import Path
import sys
import re
from sigma.configuration import SigmaConfiguration
from sigma.config.exceptions import SigmaConfigParseError

class SigmaConfigurationManager(object):
    """
    Locate Sigma configuration files in a directory and provide them as well as information
    about them.
    """
    re_identifier = re.compile("^[\\w-]+$")
    def __init__(self, paths=None):
        """
        Initialize configuration collection. If paths is not given, some default locations are used:

        * Directory config/ in current script run path
        * 'data_files' sigma config location
        * ~/.config/sigma
        * /etc/sigma

        Parameters:
        * paths: list of strings with paths
        """
        if paths is None:
            self.paths = [
                    path for path in (
                            Path(sys.path[0]) / "config",           # Script launch directory + config/
                            Path(sys.prefix) / "local/etc/sigma",   # System location of installed pip package
                            Path(sys.prefix) / "etc/sigma",        # Virtualenv location of installed pip package
                            Path.home() / ".config/sigma",          # $HOME + .config/sigma
                            Path("/etc/sigma"),
                        )
                        if path.exists()
                    ]
        elif isinstance(paths, Iterable) and all([type(path) is str for path in paths]):
            self.paths = [Path(path) for path in paths]
        else:
            raise TypeError("None or iterable of strings expected as paths")

        self.configs = dict()
        self.errors = list()
        self.update()

    def update(self):
        """Update configurations"""
        self.configs.clear()
        self.errors.clear()
        for path in reversed(self.paths):       # Configs from first paths override latter ones
            for conf_path in path.glob("**/*.yml"):
                try:
                    f = conf_path.open()
                    self.configs[conf_path.stem] = SigmaConfiguration(f)
                    f.close()
                except (SigmaConfigParseError, OSError) as e:
                    self.errors.append((conf_path, e))

    def list(self):
        """Returns a list of (identifier, title) tuples of found configurations."""
        return [ (conf_id, config.config.setdefault("title", ""), config.config.setdefault("backends", list())) for conf_id, config in self.configs.items() ]

    def get(self, name):
        """
        Return a config by identifier or file path. First, it tries to resolve identifier from
        discovered configurations (file name stem). If this fails, the parameter value is treated
        as file name.
        """
        try:                # Lookup in discovered configurations
            return self.configs[name]
        except KeyError:    # identifier not found, try with filename
            f = open(name)
            return SigmaConfiguration(f)
