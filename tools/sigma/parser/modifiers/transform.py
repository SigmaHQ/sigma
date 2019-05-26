# Sigma value modifiers
# Copyright 2019 Thomas Patzke, Florian Roth

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

from .base import SigmaTransformModifier
from .mixins import ListOrStringModifierMixin
from sigma.parser.condition import ConditionAND

class SigmaContainsModifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """Add *-wildcard before and after all string(s)"""
    identifier = "contains"
    active = True

    def apply_str(self, val : str):
        if not val.startswith("*"):
            val = "* " + val
        if not val.endswith("*"):
            val += " *"
        return val

class SigmaAllValuesModifier(SigmaTransformModifier):
    """Override default OR-linking behavior for list with AND-linking of all list values"""
    identifier = "all"
    active = True
    valid_input_types = (list, tuple, )

    def apply(self):
        vals = super().apply()
        cond = ConditionAND
        for val in self.value:
            cond.add(val)
        return cond
