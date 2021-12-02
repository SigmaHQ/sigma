# Output backends for sigmac
# Copyright 2021 Datadog, Inc.

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

import re

from sigma.backends.base import SingleTextQueryBackend
from sigma.parser.condition import NodeSubexpression


class DatadogLogsBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Datadog log search queries."""

    identifier = "datadog-logs"
    active = True
    config_required = False

    andToken = " AND "
    orToken = " OR "
    notToken = "-"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = "%s"
    mapExpression = "%s:%s"
    nullExpression = "-%s:*"
    notNullExpression = "%s:*"

    # The escaped characters list comes from https://docs.datadoghq.com/logs/explorer/search_syntax/#escaping-of-special-characters.
    specialCharactersRegexp = re.compile(r'([+\-=&|><!(){}\[\]^"~?:\\/]+)')
    whitespacesRegexp = re.compile(r"\s+")

    facets = ["index", "service", "source"]

    def __init__(self, sigmaconfig, backend_options=dict()):
        if "index" in backend_options:
            self.dd_index = backend_options["index"]

        if "service" in backend_options:
            self.dd_service = backend_options["service"]

        if "source" in backend_options:
            self.dd_source = backend_options["source"]

        if sigmaconfig.config:
            self.facets += sigmaconfig.config.get("facets", [])

        super().__init__(sigmaconfig)

    def generateQuery(self, parsed):
        nodes = []

        if hasattr(self, "dd_index"):
            nodes.append(("index", self.dd_index))

        if hasattr(self, "dd_service"):
            nodes.append(("service", self.dd_service))

        if hasattr(self, "dd_source"):
            nodes.append(("source", self.dd_source))

        if type(parsed.parsedSearch) == NodeSubexpression:
            nodes.append(parsed.parsedSearch.items)
        else:
            nodes.append(parsed.parsedSearch)

        return self.generateANDNode(nodes)

    def cleanValue(self, val):
        if type(val) == int:
            return val
        else:
            return self.whitespacesRegexp.sub(
                "?", self.specialCharactersRegexp.sub("\\\\\g<1>", val)
            )

    def generateMapItemNode(self, node):
        key, value = node
        return super().generateMapItemNode(((self.wrap_key(key)), value))

    def generateNULLValueNode(self, node):
        return super().generateNULLValueNode((self.wrap_key(node)))

    def generateNotNULLValueNode(self, node):
        return super().generateNotNULLValueNode(self.wrap_key(node))

    def wrap_key(self, key):
        if key not in self.facets:
            return "@%s" % key
        else:
            return key
