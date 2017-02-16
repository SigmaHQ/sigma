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
        try:    # definition uniqueness check
            definitionNames = set()
            for definitionName in self.parsedyaml["detection"]:
                if definitionName in definitionNames:
                    raise SigmaParseError("Definition '%s' was already defined" % (definitionName))
        except KeyError:
            raise SigmaParseError("No detection definitions found")

        try:    # tokenization
            conditions = self.parsedyaml["detection"]["condition"]
            self.condtoken = list()
            if type(conditions) == str:
                self.condtoken.append(SigmaConditionTokenizer(conditions))
            elif type(conditions) == list:
                for condition in conditions:
                    self.condtoken.append(SigmaConditionTokenizer(condition))
        except KeyError:
            raise SigmaParseError("No condition found")

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
            cond = ConditionAND()
            for key, value in definition.items():
                cond.add((key, value))

        return cond

class SigmaConditionToken:
    """Token of a Sigma condition expression"""
    TOKEN_AND  = 1
    TOKEN_OR   = 2
    TOKEN_NOT  = 3
    TOKEN_ID   = 4
    TOKEN_LPAR = 5
    TOKEN_RPAR = 6
    TOKEN_PIPE = 7
    TOKEN_ONE  = 8
    TOKEN_ALL  = 9
    TOKEN_AGG  = 10
    TOKEN_EQ   = 11
    TOKEN_LT   = 12
    TOKEN_LTE  = 13
    TOKEN_GT   = 14
    TOKEN_GTE  = 15
    TOKEN_BY   = 16

    tokenstr = [
            "INVALID",
            "AND",
            "OR",
            "NOT",
            "ID",
            "LPAR",
            "RPAR",
            "PIPE",
            "ONE",
            "ALL",
            "AGG",
            "EQ",
            "LT",
            "LTE",
            "GT",
            "GTE",
            "BY",
            ]

    def __init__(self, tokendef, match):
        self.type = tokendef[0]
        self.matched = match.group()

    def __eq__(self, other):
        if type(other) == int:      # match against type
            return self.type == other
        else:
            raise NotImplementedError("SigmaConditionToken can only be compared against token type constants")

    def __str__(self):
        return "[ Token: %s: '%s' ]" % (self.tokenstr[self.type], self.matched)

class SigmaConditionTokenizer:
    """Tokenize condition string into token sequence"""
    tokendefs = [      # list of tokens, preferred recognition in given order, (token identifier, matching regular expression). Ignored if token id == None
            (SigmaConditionToken.TOKEN_ONE,  re.compile("1 of", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_ALL,  re.compile("all of", re.IGNORECASE)),
            (None,       re.compile("[\\s\\r\\n]+")),
            (SigmaConditionToken.TOKEN_AGG,  re.compile("count|distcount|min|max|avg|sum", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_BY,   re.compile("by", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_EQ,   re.compile("==")),
            (SigmaConditionToken.TOKEN_LT,   re.compile("<")),
            (SigmaConditionToken.TOKEN_LTE,  re.compile("<=")),
            (SigmaConditionToken.TOKEN_GT,   re.compile(">")),
            (SigmaConditionToken.TOKEN_GTE,  re.compile(">=")),
            (SigmaConditionToken.TOKEN_PIPE, re.compile("\\|")),
            (SigmaConditionToken.TOKEN_AND,  re.compile("and", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_OR,   re.compile("or", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_NOT,  re.compile("not", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_ID,   re.compile("\\w+")),
            (SigmaConditionToken.TOKEN_LPAR, re.compile("\\(")),
            (SigmaConditionToken.TOKEN_RPAR, re.compile("\\)")),
            ]

    def __init__(self, condition):
        self.tokens = list()
        pos = 1

        while len(condition) > 0:
            for tokendef in self.tokendefs:     # iterate over defined tokens and try to recognize the next one
                match = tokendef[1].match(condition)
                if match:
                    if tokendef[0] != None:
                        self.tokens.append(SigmaConditionToken(tokendef, match))
                    pos += match.end()      # increase position and cut matched prefix from condition
                    condition = condition[match.end():]
                    break
            else:   # no valid token identified
                raise SigmaParseError("Unexpected token in condition at position %d")

    def __str__(self):
        return " ".join([str(token) for token in self.tokens])

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
