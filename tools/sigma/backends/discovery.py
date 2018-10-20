# Output backends for sigmac
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

import sys
import json
import re
import sigma.backends
from .base import BaseBackend
import pkgutil
import importlib
import os

def getAllSubclasses(cls):
    for subcls in cls.__subclasses__():
        yield from getAllSubclasses(subcls)
        yield cls

def getBackendList():
    """Return list of backend classes"""
    path = os.path.dirname(__file__)
    backend_classes = list()
    for finder, name, ispkg in pkgutil.iter_modules([ path ]):
        module = importlib.import_module("." + name, __package__)
        for name, cls in vars(module).items():
            if type(cls) == type and issubclass(cls, BaseBackend) and cls.active:
                backend_classes.append(cls)
    return backend_classes

def getBackendDict():
    return {cls.identifier: cls for cls in getBackendList() }

def getBackend(name):
    try:
        return getBackendDict()[name]
    except KeyError as e:
        raise LookupError("Backend not found") from e
