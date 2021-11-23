from sigma.backends.base import SingleTextQueryBackend


class DatadogBackend(SingleTextQueryBackend):
    identifier = "datadog"  # TODO: more specific?
    active = True
    config_required = False

    andToken = " AND "
    orToken = " OR "
    notToken = "-"
    subExpression = "(%s)"
    mapExpression = "%s:%s"
