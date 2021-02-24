# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke

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

from .base import BaseBackend

### Backends for development purposes

class FieldnameListBackend(BaseBackend):
    """List all fieldnames from given Sigma rules for creation of a field mapping configuration."""
    identifier = "fieldlist"
    active = True
    config_required = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields = set()

    def generateQuery(self, parsed):
        fields = list(flatten(self.generateNode(parsed.parsedSearch)))
        if parsed.parsedAgg:
            fields += self.generateAggregation(parsed.parsedAgg)
        self.fields.update(fields)

    def generateANDNode(self, node):
        return [self.generateNode(val) for val in node]

    def generateORNode(self, node):
        return self.generateANDNode(node)

    def generateNOTNode(self, node):
        return self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return [self.generateNode(value) for value in node]

    def generateMapItemNode(self, node):
        key, value = node
        return [key]

    def generateValueNode(self, node):
        return []

    def generateNULLValueNode(self, node):
        return [node.item]

    def generateNotNULLValueNode(self, node):
        return [node.item]

    def generateAggregation(self, agg):
        fields = list()
        if agg.groupfield is not None:
            fields.append(agg.groupfield)
        if agg.aggfield is not None:
            fields.append(agg.aggfield)
        return fields

    def finalize(self):
        return "\n".join(sorted(self.fields))

# Helpers
def flatten(l):
  for i in l:
      if type(i) == list:
          yield from flatten(i)
      else:
          yield i
