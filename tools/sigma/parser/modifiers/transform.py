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
from base64 import b64encode

class SigmaContainsModifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """Add *-wildcard before and after all string(s)"""
    identifier = "contains"
    active = True

    def apply_str(self, val : str):
        if not val.startswith("*"):
            val = "*" + val
        if not val.endswith("*"):
            if val.endswith("\\"):
                val += "\\*"
            else:
                val += "*"
        return val

class SigmaStartswithModifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """Add *-wildcard before and after all string(s)"""
    identifier = "startswith"
    active = True

    def apply_str(self, val : str):
        if not val.endswith("*"):
            if val.endswith("\\"):
                val += "\\*"
            else:
                val += "*"
        return val

class SigmaEndswithModifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """Add *-wildcard before and after all string(s)"""
    identifier = "endswith"
    active = True

    def apply_str(self, val : str):
        if not val.startswith("*"):
           val = '*' + val
        return val

class SigmaAllValuesModifier(SigmaTransformModifier):
    """Override default OR-linking behavior for list with AND-linking of all list values"""
    identifier = "all"
    active = True
    valid_input_types = (list, tuple, )

    def apply(self):
        vals = super().apply()
        cond = ConditionAND()
        for val in self.value:
            cond.add(val)
        return cond

class SigmaBase64Modifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """Encode strings with Base64"""
    identifier = "base64"
    active = True
    valid_input_types = ListOrStringModifierMixin.valid_input_types + (bytes,)

    def apply_str(self, val):
        if type(val) == str:
            val = val.encode()
        return b64encode(val).decode()

class SigmaBase64OffsetModifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """Encode string(s) with Base64 in all three possible shifted offsets"""
    identifier = "base64offset"
    active = True
    valid_input_types = ListOrStringModifierMixin.valid_input_types + (bytes,)

    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)

    def apply_str(self, val):
        if type(val) == str:
            val = val.encode()
        return [
                b64encode(
                    i * b' ' + val
                    )[
                        self.start_offsets[i]:
                        self.end_offsets[(len(val) + i) % 3]
                        ].decode()
                for i in range(3)
                ]

class SigmaEncodingBaseModifier(ListOrStringModifierMixin, SigmaTransformModifier):
    """
    Encode string to a byte sequence with the encoding given in the encoding property. This is
    a base class for all encoding modifiers.
    """
    identifier = "encoding-base"
    active = False
    encoding = "ascii"

    def apply_str(self, val):
        return val.encode(self.encoding)

class SigmaEncodeUTF16Modifier(SigmaEncodingBaseModifier):
    """Encode string to UTF-16 byte sequence"""
    identifier = "utf16"
    active = True
    encoding = "utf-16"

class SigmaEncodeUTF16LEModifier(SigmaEncodingBaseModifier):
    """Encode string to UTF-16 little endian byte sequence"""
    identifier = "utf16le"
    active = True
    encoding = "utf-16le"

class SigmaEncodeWideModifier(SigmaEncodeUTF16LEModifier):
    """Modifier 'wide' is an alias for the utf16le modifier."""
    identifier = "wide"

class SigmaEncodeUTF16BEModifier(SigmaEncodingBaseModifier):
    """Encode string to UTF-16 big endian byte sequence"""
    identifier = "utf16be"
    active = True
    encoding = "utf-16be"
