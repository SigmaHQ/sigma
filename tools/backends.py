# Output backends for sigmac

import json

def getBackendList():
    """Return list of backend classes"""
    return list(filter(lambda cls: type(cls) == type and issubclass(cls, BaseBackend) and cls.active, [item[1] for item in globals().items()]))

def getBackendDict():
    return {cls.identifier: cls for cls in getBackendList() }

class BaseBackend:
    """Base class for all backends"""
    identifier = "base"
    active = False

class ElasticsearchQuerystringBackend(BaseBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

class ElasticsearchDSLBackend(BaseBackend):
    """Converts Sigma rule into Elasticsearch DSL query (JSON)."""
    identifier = "es-dsl"
    active = True

class KibanaBackend(ElasticsearchDSLBackend):
    """Converts Sigma rule into Kibana JSON Configurations."""
    identifier = "kibana"
    active = True

class SplunkBackend(BaseBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "splunk"
    active = True

class NullBackend(BaseBackend):
    """Does nothing, for debugging purposes."""
    identifier = "null"
    active = True
