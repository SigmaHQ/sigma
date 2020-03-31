#!/usr/bin/env python3
# Calculates similarity of Sigma rules by transformation into a normalized
# string form and calculation of a string distance.

import argparse
import pathlib
import itertools
import difflib

import progressbar

from sigma.parser.collection import SigmaCollectionParser
from sigma.backends.base import SingleTextQueryBackend
from sigma.configuration import SigmaConfiguration

argparser = argparse.ArgumentParser(description="Calculate a similarity score between Sigma rules.")
argparser.add_argument("--recursive", "-r", action="store_true", help="Recurse into directories")
argparser.add_argument("--verbose", "-v", action="count", help="Be verbose. Use once more for debug output.")
argparser.add_argument("--top", "-t", type=int, help="Only output the n most similar rule pairs.")
argparser.add_argument("--min-similarity", "-m", type=int, help="Only output pairs with a similarity above this threshold (percent)")
argparser.add_argument("--primary", "-p", help="File with list of paths to primary rules. If given, only rule combinations with at leat one primary rule are compared. Primary rules must also be contained in input rule set.")
argparser.add_argument("inputs", nargs="+", help="Sigma input files")
args = argparser.parse_args()

def print_verbose(level, *args, **kwargs):
    if args.verbose >= level:
        print(*args, **kwargs)

class SigmaNormalizationBackend(SingleTextQueryBackend):
    """Normalization of a Sigma rule into a non-existing query language that supports all Sigma features"""
    andToken = " AND "
    orToken = " OR "
    notToken = " NOT "
    subExpression = "(%s)"
    listExpression = "[%s]"
    listSeparator = ","
    valueExpression = "%s"
    typedValueExpression = dict()
    nullExpression = "NULL(%s)"
    notNullExpression = "NOTNULL(%s)"
    mapExpression = "{'%s':'%s'}"

    sort_condition_lists = True

    def generateListNode(self, node):
        """Return sorted list"""
        return super().generateListNode(list(sorted([ str(item) for item in node ])))

    def generateTypedValueNode(self, node):
        """Return normalized form of typed values"""
        return "type_{}({})".format(node.identifier, str(node))

    def generateAggregation(self, agg):
        if agg.aggfunc_notrans == "near":
            return " near in={} ex={}".format(str(agg.include), str(agg.exclude))
        else:
            return " | {}({}) by {} {} {}".format(agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)

def main():
    backend = SigmaNormalizationBackend(SigmaConfiguration())

    if args.recursive:
        paths = [ p for pathname in args.inputs for p in pathlib.Path(pathname).glob("**/*") if p.is_file() ]
    else:
        paths = [ pathlib.Path(pathname) for pathname in args.inputs ]

    primary_paths = None
    if args.primary:
        with open(args.primary, "r") as f:
            primary_paths = { pathname.strip() for pathname in f.readlines() }

    parsed = {
                str(path): SigmaCollectionParser(path.open().read())
                for path in paths
            }
    converted = {
                str(path): list(sigma_collection.generate(backend))
                for path, sigma_collection in parsed.items()
            }
    converted_flat = (
                (path, i, normalized)
                for path, nlist in converted.items()
                for i, normalized in zip(range(len(nlist)), nlist)
            )
    converted_pairs_iter = itertools.combinations(converted_flat, 2)
    if primary_paths:
        converted_pairs = [ pair for pair in converted_pairs_iter if pair[0][0] in primary_paths or pair[1][0] in paths ]
    else:
        converted_pairs = list(converted_pairs_iter)
    similarities = [
            (item1[:2], item2[:2], difflib.SequenceMatcher(None, item1[2], item2[2]).ratio())
                for item1, item2 in progressbar.progressbar(converted_pairs)
            ]

    i = 0
    for similarity in sorted(similarities, key=lambda s: s[2], reverse=True):
        if args.min_similarity and similarity[2] * 100 < args.min_similarity:   # finish after similarity drops below minimum
            break
        print("{:70} | {:2} | {:70} | {:2} | {:>3.2%}".format(*similarity[0], *similarity[1], similarity[2]))
        i += 1
        if args.top and i >= args.top:  # end after $top pairs
            break

if __name__ == "__main__":
    main()
