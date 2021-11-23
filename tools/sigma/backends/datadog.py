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
    valueExpression = "%s" # TODO: escape string containing special chars
    mapExpression = "%s:%s"
    nullExpression = ""

    service = None

    def __init__(self, sigmaconfig, backend_options):
        if "index" in backend_options:
            self.dd_index = backend_options["index"]

        super().__init__(sigmaconfig)

    def generate(self, sigmaparser):
        self.service = sigmaparser.parsedyaml["logsource"].get("service", "")
        return super().generate(sigmaparser)

    def generateQuery(self, parsed):
        nodes = [
            self.generateMapItemNode(["service", self.service]),
            self.generateNode(parsed.parsedSearch),
        ]

        if self.dd_index:
            nodes = [self.generateMapItemNode(["index", self.dd_index])] + nodes

        return self.generateANDNode(nodes)
