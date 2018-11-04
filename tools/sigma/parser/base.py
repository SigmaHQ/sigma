# Sigma parser
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

from .exceptions import SigmaParseError

class SimpleParser:
    """
    Rule-defined parser that converts a token stream into a Python object.

    Rules are defined in the class property parsingrules, a list of dict of tuples with the following format:
    [ { token_0_0: parsing_rule_0_0, token_0_1: parsing_rule_0_1, ..., token_0_n: parsing_rule_0_n } , ... , { token_m_0: parsing_rule_m_0, ... } ]

    Each list index of parsing rules represents a parser state.
    Each parser state is defined by a dict with associates a token with a rule definition.
    The rule definition is a tuple that defines what is done next when the parser encounters a token in the current parser state:

    ( storage attribute, transformation function, next ruleset)

    * storage attribute: the name of the object attribute that is used for storage of the attribute
    * transformation method: name of an object method that is called before storage. It gets a parameter and returns the value that is stored
    * next state: next parser state

    A None value means that the action (transformation, storage or state change) is not conducted.

    A negative state has the special meaning that no further token is expected and may be used as return value.
    The set or list finalstates contains valid final states. The parser verifies after the last token that it
    has reached one of these states. if not, a parse error is raised.
    """

    def __init__(self, tokens, init_state=0):
        self.state = init_state

        for token in tokens:
            if self.state < 0:
                raise SigmaParseError("No further token expected, but read %s" % (str(token)))
            try:
                rule = self.parsingrules[self.state][token.type]
            except KeyError as e:
                raise SigmaParseError("Unexpected token %s at %d in aggregation expression" % (str(token), token.pos)) from e

            value = token.matched
            trans_value = value
            if rule[1] != None:
                trans_value = getattr(self, rule[1])(value)
            if rule[0] != None:
                setattr(self, rule[0], trans_value)
                setattr(self, rule[0] + "_notrans", value)
            if rule[2] != None:
                self.state = rule[2]
        if self.state not in self.finalstates:
            raise SigmaParseError("Unexpected end of aggregation expression, state=%d" % (self.state))

    def __str__(self):  # pragma: no cover
        return "[ Parsed: %s ]" % (" ".join(["%s=%s" % (key, val) for key, val in self.__dict__.items() ]))
