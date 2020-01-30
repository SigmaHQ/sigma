from sigma.backends.elasticsearch import ElasticsearchDSLBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.condition import SigmaAggregationParser


def test_backend_elastic():
    """
    Test aggregation of the form

    count(aggfield) by GroupField < 3
    """
    sigma_config = SigmaConfiguration()
    backend = ElasticsearchDSLBackend(sigma_config)

    # setup the aggregator input object without calling __init__()
    agg = object.__new__(SigmaAggregationParser)
    agg.condition = "3"
    agg.cond_op = "<"
    agg.aggfunc = SigmaAggregationParser.AGGFUNC_COUNT
    agg.aggfield = "aggfield"
    agg.groupfield = "GroupField"

    # Make queries non-empty
    backend.queries = [{}]

    backend.generateAggregation(agg)

    inner_agg = backend.queries[0]["aggs"]["GroupField_count"]["aggs"]
    bucket_selector = backend.queries[0]["aggs"]["GroupField_count"]["aggs"]["limit"]["bucket_selector"]
    assert len(backend.queries) == 1, "backend has exactly one query"
    assert ("GroupField_count" in backend.queries[0]["aggs"]), "GroupField_count is the top aggregation key"
    assert ("aggfield_distinct" in backend.queries[0]["aggs"]["GroupField_count"]["aggs"]), "aggfield_distinct is the nested aggregation key"
    assert ("GroupField_count" in backend.queries[0]["aggs"]), "GroupField_count is the top aggregation key"
    assert "{}.keyword".format(agg.aggfield) == inner_agg["aggfield_distinct"]["cardinality"]["field"], "inner agg field must have suffix .keyword"
    assert ("params.count < 3" in bucket_selector["script"]), "bucket selector script must be 'params.count < 3'"
    assert "count" in bucket_selector["buckets_path"], "buckets_path must be 'count'"


def test_backend_elastic_count_nofield_agg():
    """
    Test aggregation of the form

    count() by GroupedField < 3
    """

    sigma_config = SigmaConfiguration()
    backend = ElasticsearchDSLBackend(sigma_config)

    # setup the aggregator input object without calling __init__()
    agg = object.__new__(SigmaAggregationParser)
    agg.condition = "3"
    agg.cond_op = "<"
    agg.aggfunc = SigmaAggregationParser.AGGFUNC_COUNT
    agg.aggfield = None
    agg.groupfield = "GroupedField"

    # Make queries non-empty
    backend.queries = [{}]
    backend.generateAggregation(agg)
    bucket_selector = backend.queries[0]["aggs"]["GroupedField_count"]["aggs"]["limit"]["bucket_selector"]

    assert len(backend.queries) == 1, "backend has exactly one query"
    assert ("GroupedField_count" in backend.queries[0]["aggs"]), "GroupedField_count is the top aggregation key"
    assert ("params.count < 3" in bucket_selector["script"]), "bucket selector script must be 'params.count < 3'"
    assert "count" in bucket_selector["buckets_path"], "buckets_path must be 'count'"
