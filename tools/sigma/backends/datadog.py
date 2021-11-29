import re

from sigma.backends.base import SingleTextQueryBackend


class DatadogBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Datadog log search queries."""

    identifier = "datadog"  # TODO: more specific?
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
    nullExpression = ""

    # The escaped characters list comes from https://docs.datadoghq.com/logs/explorer/search_syntax/#escaping-of-special-characters.
    specialCharactersRegexp = re.compile(
        r'([\+\-\=\&\|\>\<\!\(\)\{\}\[\]\^"\~\?\:\\\/]+)'
    )
    whitespacesRegexp = re.compile(r"\s+")

    def __init__(self, sigmaconfig, backend_options):
        if "index" in backend_options:
            self.dd_index = backend_options["index"]

        super().__init__(sigmaconfig)

    def generate(self, sigmaparser):
        if "service" in sigmaparser.parsedyaml.get("logsource", {}):
            self.dd_service = sigmaparser.parsedyaml["logsource"]["service"]

        return super().generate(sigmaparser)

    def generateQuery(self, parsed):
        nodes = []

        if hasattr(self, "dd_index"):
            nodes.append(("index", self.dd_index))

        if hasattr(self, "dd_service"):
            nodes.append(("service", self.dd_service))

        nodes.append(parsed.parsedSearch)

        return self.generateANDNode(nodes)

    def cleanValue(self, val):
        if type(val) == int:
            return val
        else:
            return self.whitespacesRegexp.sub(
                "?", self.specialCharactersRegexp.sub("\\\\\g<1>", val)
            )
