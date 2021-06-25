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
from ipaddress import ip_network

### Backends for developement purposes

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
        if type(value) not in (str, int, list, type(None)):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
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

def generatelistforcidrv4 (fieldname : str,ip_str : str, Separator_str : str, explose : bool):
    """ the network CIDR brain """
    
    if ',' in ip_str:
        list_ip_str = ip_str.split(',')
    else:
        list_ip_str = [ip_str]
  
    list_field_ip = []    
    for cidr in list_ip_str:
        if explose :
            subnet = int (str(cidr).split('/')[1])
            if subnet <= 8 :
                new_sub = 8
                remp_old = '0/8'
                remp_new = '*'
            elif subnet <= 16:
                new_sub = 16
                remp_old = '0/16'
                remp_new = '*'
            elif subnet <= 24:
                new_sub = 24
                remp_old = '0/24'
                remp_new = '*'
            elif subnet <= 32:
                new_sub = 32
                remp_old = '/32'
                remp_new = ''
            ip_range = list(ip_network(str(cidr)).subnets(new_prefix=new_sub))
            list_ip = [str(ip_sub).replace(remp_old,remp_new) for ip_sub in ip_range]
        else:
            list_ip = [cidr]
            
        for term in list_ip:
            list_field_ip.append(str(fieldname+': '+ term))
    str_ip = Separator_str.join(list_field_ip)
    return str_ip
    