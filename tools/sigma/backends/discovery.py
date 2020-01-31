# Output backend discovery
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

import sys
import json
import re
import os
import sigma.backends
from .base import BaseBackend
from sigma.tools import getAllSubclasses, getClassDict

def getBackendList():
    """Return list of backend classes"""
    path = os.path.dirname(__file__)
    return getAllSubclasses(path, "backends", BaseBackend)

def getBackendDict():
    return getClassDict(getBackendList())

def getBackend(name):
    try:
        return getBackendDict()[name]
    except KeyError as e:
        raise LookupError("Backend not found") from e
