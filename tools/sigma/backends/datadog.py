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

    service = None

    def generate(self, sigmaparser):
        self.service = sigmaparser.parsedyaml['logsource'].get('service', "")
        return super().generate(sigmaparser)

    def generateQuery(self, parsed):
        return self.generateANDNode([
            self.generateMapItemNode(["service", self.service]),
            self.generateNode(parsed.parsedSearch),
        ])
