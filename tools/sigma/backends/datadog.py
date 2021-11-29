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
    valueExpression = "%s"  # TODO: escape string containing special chars
    mapExpression = "%s:%s"
    nullExpression = ""

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
            nodes.append(self.generateMapItemNode(["index", self.dd_index]))

        if hasattr(self, "dd_service"):
            nodes.append(self.generateMapItemNode(["service", self.dd_service]))

        nodes.append(self.generateNode(parsed.parsedSearch))

        return self.generateANDNode(nodes)
