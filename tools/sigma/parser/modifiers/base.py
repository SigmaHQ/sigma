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

from enum import Enum, auto
from .exceptions import SigmaModifierValueTypeError

class SigmaModifierTypes(Enum):
    NONE = auto()
    TRANSFORM = auto()
    TYPE = auto()

class SigmaModifier(object):
    """
    Value modifier base class. There are two modifier types (with separate base classes):

    identifier: identifier string that is used in Sigma rules to use modifier
    active: boolean if modifier will be found by autodiscovery (and therefore usable)
    modifier_type: type from SigmaModifierTypes enumeration
        * Value transformation modifiers: the value or list of values is transformed to a different
            value or a list of values. Base class: SigmaValueModifier
        * Type modifiers: modify the type of the modifier, e.g. to support regular expressions. The
            backend must handle these modifiers accordingly. Base class: SigmaTypeModifier
    valid_input_types: list of valid input types. Can be expected Python type (like str, int) or
        modifier class. object = don't care about type.
    """
    identifier = "base"
    active = False
    modifier_type = SigmaModifierTypes.NONE
    valid_input_types = (object,)

    def __init__(self, value):
        """Initialize modifier class. Store value or result of value transformation."""
        self.value = value
        if not self.validate():
            raise SigmaModifierValueTypeError

    def validate(self):
        """Validate if modifier is applicable to value. Expects that value is stored in self.value."""
        return any(( isinstance(self.value, t) for t in self.valid_input_types ))

    def apply(self):
        """
        Apply modifier to value. This method can:
        * Return a transformed value
        * Return a list of values
        * Return an object from sigma.parser.condition that replaces the value in the condition tree
        * Return a value that is used by dedicated type modifier code in the backend to get a final
            query statement (only for type modifiers)

        The base method simply returns the stored value.
        """
        try:
            return self.value.apply()
        except AttributeError:
            return self.value

class SigmaTransformModifier(SigmaModifier):
    """Transform a value into a different value or a list of values"""
    identifier = "tansform_base"
    modifier_type = SigmaModifierTypes.TRANSFORM

class SigmaTypeModifier(SigmaModifier):
    """Modify the type of the value. This must be handled by the backend."""
    identifier = "type_base"
    modifier_type = SigmaModifierTypes.TYPE

    def apply(self):
        return self

    def __str__(self):
        return str(self.value)
