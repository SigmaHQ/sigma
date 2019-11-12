from sigma.backends.elasticsearch import ElasticsearchDSLBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.condition import SigmaAggregationParser


def test_backend_elastic():
    sigma_config = SigmaConfiguration()
    backend = ElasticsearchDSLBackend(sigma_config)

    # setup the aggregator input object without calling __init__()
    agg = object.__new__(SigmaAggregationParser)
    agg.condition = "3"
    agg.cond_op = "<"
    agg.aggfunc = SigmaAggregationParser.AGGFUNC_COUNT
    agg.aggfield = "aggfield"
    agg.groupfield = "groupfield"

    # Make queries non-empty
    backend.queries = [{}]

    backend.generateAggregation(agg)

    assert len(backend.queries) == 1, "backend has exactly one query"
    assert (
        "groupfield_count" in backend.queries[0]["aggs"]["aggs"]
    ), "groupfield_count is the top aggregation key"
    assert (
        "aggfield_distinct"
        in backend.queries[0]["aggs"]["aggs"]["groupfield_count"]["aggs"]
    ), "aggfield_distinct is the nested aggregation key"
