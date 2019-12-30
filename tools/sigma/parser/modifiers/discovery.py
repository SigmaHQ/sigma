# Discovery of modifier modules
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

import os
from sigma.tools import getAllSubclasses, getClassDict
from .base import SigmaModifier

def getModifierList():
    """Return list of modifier classes"""
    path = os.path.dirname(__file__)
    return getAllSubclasses(path, "parser.modifiers", SigmaModifier)

modifiers = getClassDict(getModifierList())

def apply_modifiers(value, modifier_list):
    """
    Apply modifiers to value.

    value: value from Sigma rule
    modifiers: list of modifier names
    """
    for modifier in modifier_list:      # apply modifiers in given order
        value = modifiers[modifier](value).apply()
    return value
