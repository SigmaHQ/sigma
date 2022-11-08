# Code used across all Sigma modules
# Copyright 2016-2019 Thomas Patzke, Florian Roth

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

import pkgutil
import importlib

def getAllSubclasses(path, import_base, base_class):
    """Return list of all classes derived from a superclass contained in a module."""
    classes = set()
    for finder, name, ispkg in pkgutil.iter_modules([ path ]):
        module = importlib.import_module(".{}.{}".format(import_base, name), __package__)
        for name, cls in vars(module).items():
            if type(cls) == type and issubclass(cls, base_class) and cls.active:
                classes.add(cls)
    return classes

def getClassDict(clss):
    """Return a dictionary: class.identifier -> class"""
    return {cls.identifier: cls for cls in clss }
