# Sigma parser

import yaml
import re

COND_NONE = 0
COND_AND  = 1
COND_OR   = 2
COND_NOT  = 3

class SigmaParser:
    def __init__(self, sigma):
        self.definitions = dict()
        self.parsedyaml = yaml.safe_load(sigma)
        try:
            for definitionName in self.parsedyaml["detection"]:
                if definitionName in ("condition", "timeframe"):       # skip non-identifiers here
                    continue
                if definitionName in self.definitions:
                    raise SigmaParseError("Definition '%s' was already defined" % (definitionName))
                self.definitions[definitionName] = self.parse_definition(self.parsedyaml["detection"][definitionName])
        except KeyError:
            raise SigmaParseError("No detection definitions found")

    def parse_definition(self, definition, condOverride=None):
        if type(definition) not in (dict, list):
            raise SigmaParseError("Expected map or list, got type %s: '%s'" % (type(definition), str(definition)))

        if type(definition) == list:    # list of values or maps
            if condOverride:    # condition given through rule detection condition, e.g. 1 of x
                cond = condOverride
            else:               # no condition given, use default from spec
                cond = ConditionOR()

            for value in definition:
                if type(value) in (str, int, dict):
                    cond.add(value)
                else:
                    raise SigmaParseError("Definition list may only contain plain values or maps")
        elif type(definition) == dict:      # map
            cond = definition

        return cond

class SigmaParseError(Exception):
    pass

### Parse Tree Node Classes ###
class ConditionBase:
    """Base class for conditional operations"""
    op = COND_NONE
    items = None

    def __init__(self):
        raise NotImplementedError("ConditionBase is no usable class")

    def add(self, item):
        self.items.append(item)

class ConditionAND(ConditionBase):
    """AND Condition"""
    op = COND_AND

    def __init__(self):
        self.items = list()

class ConditionOR(ConditionAND):
    """OR Condition"""
    op = COND_OR

class ConditionNOT(ConditionBase):
    """NOT Condition"""
    op = COND_NOT

    def __init__(self):
        self.items = None

    def add(self, item):
        if self.items == None:
            super.add(item)
        else:
            raise ValueError("Only one element allowed in NOT condition")
