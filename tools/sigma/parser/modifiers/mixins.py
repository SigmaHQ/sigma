# Sigma modifier mixins
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

from sigma.parser.condition import ConditionAND, ConditionBase, ConditionOR, NodeSubexpression


class ListOrStringModifierMixin(object):
    """
    Definitions and convenience methods for modifiers that can be applied to lists and strings.

    Defines appropriate valid_input_types and takes care that method apply_str() or apply_list()
    is called.

    Default behaviors:
    * apply_list() calls apply_str(str) for each value and returns list with all results.
    * apply_str(str) returns string without modifications
    """
    valid_input_types = (list, tuple, str, )

    def apply(self):
        if isinstance(self.value, (list, tuple, ConditionBase, NodeSubexpression)):
            return self.apply_list(self.value)
        else:
            return self.apply_str(self.value)

    def apply_list(self, l):
        """Method is called if modifier value contains a list"""
        if isinstance(l, (list, tuple)):
            l = [
                self.apply_str(v)
                if isinstance(v, str)
                else self.apply_list(v)
                for v in l ]
            rl = list()
            for i in l:
                if type(i) in { list, tuple, set }:
                    rl.extend(i)
                else:
                    rl.append(i)
            return rl
        elif isinstance(l, NodeSubexpression):
            return NodeSubexpression(self.apply_list(l.items))
        elif isinstance(l, ( ConditionOR, ConditionAND )):
            cond = l.__class__()
            cond.items = self.apply_list(l.items)
            return cond

    def apply_str(self, val : str):
        """Method is called if modifier input value contains a string or once for each list element"""
        return val
