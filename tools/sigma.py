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

    def parse_sigma(self):
        try:    # definition uniqueness check
            for definitionName, definition in self.parsedyaml["detection"].items():
                if definitionName in self.definitions:
                    raise SigmaParseError("Definition '%s' was already defined" % (definitionName))
                self.definitions[definitionName] = definition
        except KeyError:
            raise SigmaParseError("No detection definitions found")

        try:    # tokenization
            conditions = self.parsedyaml["detection"]["condition"]
            self.condtoken = list()     # list of tokenized conditions
            if type(conditions) == str:
                self.condtoken.append(SigmaConditionTokenizer(conditions))
            elif type(conditions) == list:
                for condition in conditions:
                    self.condtoken.append(SigmaConditionTokenizer(condition))
        except KeyError:
            raise SigmaParseError("No condition found")

        self.condparsed = list()        # list of parsed conditions
        for tokens in self.condtoken:
            self.condparsed.append(SigmaConditionParser(self, tokens))

    def parse_definition(self, definitionName, condOverride=None):
        try:
            definition = self.definitions[definitionName]
        except KeyError as e:
            raise SigmaParseError("Unknown definition '%s'" % (definitionName)) from e
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

    def __init__(self, tokendef, match, pos):
        self.type = tokendef[0]
        self.matched = match.group()
        self.pos = pos

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
                        self.tokens.append(SigmaConditionToken(tokendef, match, pos + match.start()))
                    pos += match.end()      # increase position and cut matched prefix from condition
                    condition = condition[match.end():]
                    break
            else:   # no valid token identified
                raise SigmaParseError("Unexpected token in condition at position %d")

    def __str__(self):
        return " ".join([str(token) for token in self.tokens])

    def __iter__(self):
        return iter(self.tokens)

    def __getitem__(self, i):
        return self.tokens[i]

    def index(self, item):
        return self.tokens.index(item)
                
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

    def __init__(self, sigma=None, op=None, val1=None, val2=None):
        if sigma == None and op == None and val1 == None and val2 == None:    # no parameters given - initialize empty
            self.items = list()
        else:       # called by parser, use given values
            self.items = [ val1, val2 ]

class ConditionOR(ConditionAND):
    """OR Condition"""
    op = COND_OR

class ConditionNOT(ConditionBase):
    """NOT Condition"""
    op = COND_NOT

    def __init__(self, sigma=None, op=None, val=None):
        if sigma == None and op == None and val == None:    # no parameters given - initialize empty
            self.items = None
        else:       # called by parser, use given values
            self.items = val

    def add(self, item):
        if self.items == None:
            super.add(item)
        else:
            raise ValueError("Only one element allowed in NOT condition")

class NodeSubexpression:
    """Subexpression in parentheses"""
    def __init__(self, subexpr):
        self.subexpr = subexpr

# Parse tree converters: convert something into one of the parse tree node classes defined above
def convertAllFrom(sigma, op, val):
    """Convert 'all from x' into ConditionAND"""
    return sigma.parse_definition(val, ConditionAND)

def convertOneFrom(sigma, op, val):
    """Convert '1 from x' into ConditionOR"""
    return sigma.parse_definition(val, ConditionAND)

def convertId(sigma, op):
    """Convert search identifiers (lists or maps) into condition nodes according to spec defaults"""
    return sigma.parse_definition(op.matched)

# Condition parser class
class SigmaConditionParser:
    """Parser for Sigma condition expression"""
    searchOperators = [     # description of operators: (token id, number of operands, parse tree node class) - order == precedence
            (SigmaConditionToken.TOKEN_ALL, 1, convertAllFrom),
            (SigmaConditionToken.TOKEN_ONE, 1, convertOneFrom),
            (SigmaConditionToken.TOKEN_ID,  0, convertId),
            (SigmaConditionToken.TOKEN_NOT, 1, ConditionNOT),
            (SigmaConditionToken.TOKEN_AND, 2, ConditionAND),
            (SigmaConditionToken.TOKEN_OR,  2, ConditionOR),
            ]

    def __init__(self, sigmaParser, tokens):
        if SigmaConditionToken.TOKEN_PIPE in tokens:    # aggregations are not yet supported
            raise NotImplementedError("Aggregation expressions are not yet supported")

        self.sigmaParser = sigmaParser
        parsedSearch = self.parseSearch(tokens)

    def parseSearch(self, tokens):
        """
        Iterative parsing of search expression.
        """
        # 1. Identify subexpressions with parentheses around them and parse them like a separate search expression
        while SigmaConditionToken.TOKEN_LPAR in tokens:
            lPos = tokens.index(SigmaConditionToken.TOKEN_LPAR)
            lTok = tokens[lPos]
            try:
                rPos = tokens.index(SigmaConditionToken.TOKEN_RPAR)
                rTok = tokens[rPos]
            except ValueError as e:
                raise SigmaParseError("Missing matching closing parentheses") from e
            if lPos + 1 == rPos:
                raise SigmaParseError("Empty subexpression at " + str(lTok.pos))
            if lPos > rPos:
                raise SigmaParseError("Closing parentheses at position " + str(rTok.pos) + " precedes opening at position " + str(lTok.pos))

            subparsed = self.parseSearch(tokens[lPos + 1:rPos - 1])
            tokens = tokens[:lPos] + [ NodeSubexpression(subparsed) ] + tokens[rPos + 1:]   # replace parentheses + expression with group node that contains parsed subexpression

        # 2. Iterate over all known operators in given precedence
        for operator in self.searchOperators:
            # 3. reduce all occurrences into corresponding parse tree nodes
            while operator[0] in tokens:
                print(tokens)
                pos_op = tokens.index(operator[0])
                tok_op = tokens[pos_op]
                if operator[1] == 0:    # operator
                    treenode = operator[2](self.sigmaParser, tok_op)
                    tokens = tokens[:pos_op] + [ treenode ] + tokens[pos_op + 1:]
                elif operator[1] == 1:    # operator value
                    pos_val = pos_op + 1
                    tok_val = tokens[pos_val]
                    treenode = operator[2](self.sigmaParser, tok_op, tok_val)
                    tokens = tokens[:pos_op] + [ treenode ] + tokens[pos_val + 1:]
                elif operator[1] == 2:    # value1 operator value2
                    print(operator, pos_op)
                    pos_val1 = pos_op - 1
                    pos_val2 = pos_op + 1
                    tok_val1 = tokens[pos_val1]
                    tok_val2 = tokens[pos_val2]
                    treenode = operator[2](self.sigmaParser, tok_op, tok_val1, tok_val2)
                    tokens = tokens[:pos_val1] + [ treenode ] + tokens[pos_val2 + 1:]
        return tokens
