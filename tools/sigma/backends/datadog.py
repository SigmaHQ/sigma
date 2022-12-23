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

from re import compile
from sigma.backends.base import SingleTextQueryBackend
from sigma.parser.condition import NodeSubexpression


class DatadogLogsBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Datadog log search query."""

    identifier = "datadog-logs"
    active = True
    config_required = False

    andToken = " AND "
    orToken = " OR "
    notToken = "-"
    subExpression = "(%s)"
    listExpression = "(%s)"
    # List selection items are linked with a logical 'OR' per the Sigma specification:
    # https://github.com/SigmaHQ/sigma/wiki/Specification#lists.
    listSeparator = " OR "
    valueExpression = "%s"
    mapExpression = "%s:%s"
    nullExpression = "-%s:*"
    notNullExpression = "%s:*"

    # The escaped characters list comes from https://docs.datadoghq.com/logs/explorer/search_syntax/#escaping-of-special-characters.
    specialCharactersRegexp = compile(r'([+\-=&|><!(){}\[\]^"~?:\\/]+)')
    whitespacesRegexp = compile(r"\s")

    # Default tags taken from https://docs.datadoghq.com/getting_started/tagging/#introduction.
    tags = {}

    def __init__(self, sigmaconfig, backend_options=None):

        if sigmaconfig.config:
            self.dd_index = sigmaconfig.config.get("index")
            self.dd_service = sigmaconfig.config.get("service")
            self.dd_source = sigmaconfig.config.get("source")
            self.dd_env = sigmaconfig.config.get("env")
            self.tags = sigmaconfig.config.get("tags")

        # if backend_options defined, overwrite default config file (for retro-compatibility)
        if backend_options is None:
            backend_options = {}

        if "index" in backend_options:
            self.dd_index = backend_options["index"]

        if "service" in backend_options:
            self.dd_service = backend_options["service"]

        if "source" in backend_options:
            self.dd_source = backend_options["source"]

        if "env" in backend_options:
            self.dd_env = backend_options["env"]

        super().__init__(sigmaconfig)

    def generateQuery(self, parsed):
        nodes = []

        if hasattr(self, "dd_index") and self.dd_index != None:
            nodes.append(("index", self.dd_index))

        if hasattr(self, "dd_service") and self.dd_service != None:
            nodes.append(("service", self.dd_service))

        if hasattr(self, "dd_source") and self.dd_source != None:
            nodes.append(("source", self.dd_source))

        if hasattr(self, "dd_env") and self.dd_env != None:
            nodes.append(("env", self.dd_env))

        if type(parsed.parsedSearch) == NodeSubexpression:
            nodes.append(parsed.parsedSearch.items)
        else:
            nodes.append(parsed.parsedSearch)

        return self.generateANDNode(nodes)

    def cleanValue(self, val):
        if type(val) == int:
            return val
        else:
            # Whitespaces characters are replaced with a `?`.
            # Datadog also supports escaping whitespaces by double quoting
            # expression, but at the cost of losing the `*` pattern matching
            # syntax that we wanted to preserve.
            # Note that technically, `?` matches  **any** single character.
            return self.whitespacesRegexp.sub(
                # Special characters are escaped with a `\` which requires to be escaped
                # in Python as well (see https://docs.python.org/3/library/re.html).
                # This explains the unusual number of `\` in the following regex definition.
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
        if key not in self.tags and key not in ['index', 'service', 'source', 'env']:
            # print("WARNING tag %s not converted" % format(key))
            return "@%s" % key
        elif key not in ['index', 'service', 'source', 'env']:
            return self.tags[key]
        else:
            return key
