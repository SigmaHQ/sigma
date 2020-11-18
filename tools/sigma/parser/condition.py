# Sigma parser
# Copyright 2016-2017 Thomas Patzke, Florian Roth

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
from .base import SimpleParser
from .exceptions import SigmaParseError

COND_NONE = 0
COND_AND  = 1
COND_OR   = 2
COND_NOT  = 3
COND_NULL = 4


# Debugging code
def dumpNode(node, indent=''):   # pragma: no cover
    """
    Recursively print the AST rooted at *node* for debugging.
    """
    if hasattr(node, 'items'):
        print("%s%s<%s>" % (indent, type(node).__name__,
                            type(node.items).__name__))
        if type(node.items) != list:
            dumpNode(node.items, indent + '  ')
        else:
            for item in node.items:
                dumpNode(item, indent + '  ')
    else:
        print("%s%s=%s" % (indent, type(node).__name__,
                                   repr(node)))
    return node


# Condition Tokenizer
class SigmaConditionToken:
    """Token of a Sigma condition expression"""
    TOKEN_AND    = 1
    TOKEN_OR     = 2
    TOKEN_NOT    = 3
    TOKEN_ID     = 4
    TOKEN_LPAR   = 5
    TOKEN_RPAR   = 6
    TOKEN_PIPE   = 7
    TOKEN_ONE    = 8
    TOKEN_ALL    = 9
    TOKEN_AGG    = 10
    TOKEN_EQ     = 11
    TOKEN_LT     = 12
    TOKEN_LTE    = 13
    TOKEN_GT     = 14
    TOKEN_GTE    = 15
    TOKEN_BY     = 16
    TOKEN_NEAR   = 17

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
            "NEAR",
            ]

    def __init__(self, tokendef, match, pos):
        self.type = tokendef[0]
        self.matched = match.group()
        self.pos = pos

    def __eq__(self, other):
        if type(other) == int:      # match against type
            return self.type == other
        if type(other) == str:      # match against content
            return self.matched == other
        else:
            raise NotImplementedError("SigmaConditionToken can only be compared against token type constants")

    def __str__(self):  # pragma: no cover
        return "[ Token: %s: '%s' ]" % (self.tokenstr[self.type], self.matched)


class SigmaConditionTokenizer:
    """Tokenize condition string into token sequence"""
    tokendefs = [      # list of tokens, preferred recognition in given order, (token identifier, matching regular expression). Ignored if token id == None
            (SigmaConditionToken.TOKEN_ONE,    re.compile("1 of", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_ALL,    re.compile("all of", re.IGNORECASE)),
            (None,       re.compile("[\\s\\r\\n]+")),
            (SigmaConditionToken.TOKEN_AGG,    re.compile("count|min|max|avg|sum", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_NEAR,   re.compile("near", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_BY,     re.compile("by", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_EQ,     re.compile("==")),
            (SigmaConditionToken.TOKEN_LT,     re.compile("<")),
            (SigmaConditionToken.TOKEN_LTE,    re.compile("<=")),
            (SigmaConditionToken.TOKEN_GT,     re.compile(">")),
            (SigmaConditionToken.TOKEN_GTE,    re.compile(">=")),
            (SigmaConditionToken.TOKEN_PIPE,   re.compile("\\|")),
            (SigmaConditionToken.TOKEN_AND,    re.compile("and", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_OR,     re.compile("or", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_NOT,    re.compile("not", re.IGNORECASE)),
            (SigmaConditionToken.TOKEN_ID,     re.compile("[\\w*]+")),
            (SigmaConditionToken.TOKEN_LPAR,   re.compile("\\(")),
            (SigmaConditionToken.TOKEN_RPAR,   re.compile("\\)")),
            ]

    def __init__(self, condition):
        if type(condition) == str:          # String that is parsed
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
                    raise SigmaParseError("Unexpected token in condition at position %s" % condition)
        elif type(condition) == list:       # List of tokens to be converted into SigmaConditionTokenizer class
            self.tokens = condition
        else:
            raise TypeError("SigmaConditionTokenizer constructor expects string or list, got %s" % (type(condition)))

    def __str__(self):  # pragma: no cover
        return " ".join([str(token) for token in self.tokens])

    def __iter__(self):
        return iter(self.tokens)

    def __len__(self):
        return len(self.tokens)

    def __getitem__(self, i):
        if type(i) == int:
            return self.tokens[i]
        elif type(i) == slice:
            return SigmaConditionTokenizer(self.tokens[i])
        else:
            raise IndexError("Expected index or slice")

    def __add__(self, other):
        if isinstance(other, SigmaConditionTokenizer):
            return SigmaConditionTokenizer(self.tokens + other.tokens)
        elif isinstance(other, (SigmaConditionToken, ParseTreeNode)):
            return SigmaConditionTokenizer(self.tokens + [ other ])
        else:
            raise TypeError("+ operator expects SigmaConditionTokenizer or token type, got %s: %s" % (type(other), str(other)))

    def index(self, item):
        return self.tokens.index(item)


### Parse Tree Node Classes ###
class ParseTreeNode:
    """Parse Tree Node Base Class"""
    def __init__(self):
        raise NotImplementedError("ConditionBase is no usable class")

    def __str__(self):  # pragma: no cover
        return "[ %s: %s ]" % (self.__doc__, str([str(item) for item in self.items]))


class ConditionBase(ParseTreeNode):
    """Base class for conditional operations"""
    op = COND_NONE
    items = None

    def __init__(self):
        raise NotImplementedError("ConditionBase is no usable class")

    def add(self, item):
        self.items.append(item)

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)


class ConditionAND(ConditionBase):
    """AND Condition"""
    op = COND_AND

    def __init__(self, sigma=None, op=None, *args):
        if sigma == None and op == None and len(args) == 0:    # no parameters given - initialize empty
            self.items = list()
        else:       # called by parser, use given values
            self.items = args


class ConditionOR(ConditionAND):
    """OR Condition"""
    op = COND_OR


class ConditionNOT(ConditionBase):
    """NOT Condition"""
    op = COND_NOT

    def __init__(self, sigma=None, op=None, val=None):
        if sigma == None and op == None and val == None:    # no parameters given - initialize empty
            self.items = list()
        else:       # called by parser, use given values
            self.items = [ val ]

    def add(self, item):
        if len(self.items) == 0:
            super.add(item)
        else:
            raise ValueError("Only one element allowed")

    @property
    def item(self):
        try:
            return self.items[0]
        except IndexError:
            return None


class ConditionNULLValue(ConditionNOT):
    """Condition: Field value is empty or doesn't exists"""
    pass


class ConditionNotNULLValue(ConditionNULLValue):
    """Condition: Field value is not empty"""
    pass


class NodeSubexpression(ParseTreeNode):
    """Subexpression"""
    def __init__(self, subexpr):
        self.items = subexpr


# Parse tree generators: generate parse tree nodes from extended conditions
def generateXOf(sigma, val, condclass):
    """
    Generic implementation of (1|all) of x expressions.
        
    * condclass across all list items if x is name of definition
    * condclass across all definitions if x is keyword 'them'
    * condclass across all matching definition if x is wildcard expression, e.g. 'selection*'
    """
    if val.matched == "them":           # OR across all definitions
        cond = condclass()
        for name, definition in sigma.definitions.items():
            if name == "timeframe":
                continue
            cond.add(NodeSubexpression(sigma.parse_definition(definition)))
        return NodeSubexpression(cond)
    elif val.matched.find("*") > 0:     # OR across all matching definitions
        cond = condclass()
        reDefPat = re.compile("^" + val.matched.replace("*", ".*") + "$")
        for name, definition in sigma.definitions.items():
            if name != "timeframe" and reDefPat.match(name):
                cond.add(NodeSubexpression(sigma.parse_definition(definition)))
        return NodeSubexpression(cond)
    else:                               # OR across all items of definition
        return NodeSubexpression(sigma.parse_definition_byname(val.matched, condclass))


def generateAllOf(sigma, op, val):
    """Convert 'all of x' expressions into ConditionAND"""
    return generateXOf(sigma, val, ConditionAND)


def generateOneOf(sigma, op, val):
    """Convert '1 of x' expressions into ConditionOR"""
    return generateXOf(sigma, val, ConditionOR)


def convertId(sigma, op):
    """Convert search identifiers (lists or maps) into condition nodes according to spec defaults"""
    return NodeSubexpression(sigma.parse_definition_byname(op.matched))


# Optimizer
class SigmaConditionOptimizer:
    """
    Optimizer for the parsed AST.
    """
    def _stripSubexpressionNode(self, node):
        """
        Recursively strips all subexpressions (i.e. brackets) from the AST.
        """
        if type(node) == NodeSubexpression:
            assert(type(node.items) != list)
            return self._stripSubexpressionNode(node.items)
        if hasattr(node, 'items') and type(node) is not ConditionNOT:
            node.items = list(map(self._stripSubexpressionNode, node.items))
        return node

    def _unstripSubexpressionNode(self, node):
        """
        Recursively adds brackets around AND and OR operations in the AST.
        """
        if type(node) in (ConditionAND, ConditionOR):
            newnode = NodeSubexpression(node)
            node.items = list(map(self._unstripSubexpressionNode, node.items))
            return newnode
        return node

    def _ordered_uniq(self, l):
        """
        Remove duplicate entries in list *l* while preserving order.

        Used to be fast before it needed to work around list instead of
        tuple being used for lists within definitions in the AST.
        """
        seen = set()
        #return [x for x in l if x not in seen and not seen.add(x)]
        uniq = []
        for x in l:
            if type(x) == tuple and type(x[1]) == list:
                x = (x[0], tuple(x[1]))
            if x not in seen and not seen.add(x):
                uniq.append(x)
        out = []
        for x in uniq:
            if type(x) == tuple and type(x[1]) == tuple:
                out.append((x[0], list(x[1])))
            else:
                out.append(x)
        return out

    def _optimizeNode(self, node, changes=False):
        """
        Recursively optimize the AST rooted at *node* once.  Returns the new
        root node and a boolean indicating if the tree was changed in this
        invocation or any of the recursive sub-invocations.

        You MUST remove all subexpression nodes from the AST before calling
        this function.  Subexpressions are implicit around AND/OR nodes.
        """
        if type(node) in (ConditionOR, ConditionAND):
            # Remove empty OR(X), AND(X)
            if len(node.items) == 0:
                return None, True
            if None in node.items:
                node.items = [item for item in node.items if item != None]
                return self._optimizeNode(node, changes=True)

            # OR(X), AND(X)                 =>  X
            if len(node.items) == 1:
                return self._optimizeNode(node.items[0], changes=True)

            # OR(X, X, ...), AND(X, X, ...) =>  OR(X, ...), AND(X, ...)
            uniq_items = self._ordered_uniq(node.items)
            if len(uniq_items) < len(node.items):
                node.items = uniq_items
                return self._optimizeNode(node, changes=True)

            # OR(X, OR(Y))                  =>  OR(X, Y)
            if any(type(child) == type(node) for child in node.items) and \
               all(type(child) in (type(node), tuple) for child in node.items):
                newitems = []
                for child in node.items:
                    if hasattr(child, 'items'):
                        newitems.extend(child.items)
                    else:
                        newitems.append(child)
                node.items = newitems
                return self._optimizeNode(node, changes=True)

            # OR(AND(X, ...), AND(X, ...))  =>  AND(X, OR(AND(...), AND(...)))
            if type(node) == ConditionOR:
                othertype = ConditionAND
            else:
                othertype = ConditionOR
            if all(type(child) == othertype for child in node.items):
                promoted = []
                for cand in node.items[0]:
                    if all(cand in child for child in node.items[1:]):
                        promoted.append(cand)
                if len(promoted) > 0:
                    for child in node.items:
                        for cand in promoted:
                            child.items.remove(cand)
                    newnode = othertype()
                    newnode.items = promoted
                    newnode.add(node)
                    return self._optimizeNode(newnode, changes=True)

            # fallthrough

        elif type(node) == ConditionNOT:
            assert(len(node.items) == 1)
            # NOT(NOT(X))                   =>  X
            if type(node.items[0]) == ConditionNOT:
                assert(len(node.items[0].items) == 1)
                return self._optimizeNode(node.items[0].items[0], changes=True)

            # NOT(ConditionNULLValue)       =>  ConditionNotNULLValue
            if type(node.items[0]) == ConditionNULLValue:
                newnode = ConditionNotNULLValue(val=node.items[0].items[0])
                return self._optimizeNode(newnode, changes=True)

            # NOT(ConditionNotNULLValue)    =>  ConditionNULLValue
            if type(node.items[0]) == ConditionNotNULLValue:
                newnode = ConditionNULLValue(val=node.items[0].items[0])
                return self._optimizeNode(newnode, changes=True)

            # fallthrough

        else:
            return node, changes

        itemresults = [self._optimizeNode(item, changes) for item in node.items]
        node.items = [res[0] for res in itemresults]
        if any(res[1] for res in itemresults):
            changes = True
        return node, changes

    def optimizeTree(self, tree):
        """
        Optimize the boolean expressions in the AST rooted at *tree*.

        The main idea behind optimizing the AST is that less repeated terms is
        generally better for backend performance.  This is especially relevant
        to backends that do not perform any query language optimization down
        the road, such as those that generate code.

        A common example for when these suboptimal rules actually occur in
        practice is when a rule has multiple alternative detections that are
        OR'ed together in the condition, and all of the detections include a
        common element, such as the same EventID.

        The following optimizations are currently performed:
        -   Removal of empty OR(), AND()
        -   OR(X), AND(X)                 =>  X
        -   OR(X, X, ...), AND(X, X, ...) =>  OR(X, ...), AND(X, ...)
        -   OR(X, OR(Y))                  =>  OR(X, Y)
        -   OR(AND(X, ...), AND(X, ...))  =>  AND(X, OR(AND(...), AND(...)))
        -   NOT(NOT(X))                   =>  X
        -   NOT(ConditionNULLValue)       =>  ConditionNotNULLValue
        -   NOT(ConditionNotNULLValue)    =>  ConditionNULLValue

        Boolean logic simplification is NP-hard.  To avoid backtracking,
        speculative transformations that may or may not lead to a more optimal
        expression were not implemented.  These include for example factoring
        out common operands that are not in all, but only some AND()s within an
        OR(), or vice versa.  Nevertheless, it is safe to assume that this
        implementation performs poorly on very large expressions.
        """
        tree = self._stripSubexpressionNode(tree)
        changes = True
        while changes:
            tree, changes = self._optimizeNode(tree)
        tree = self._unstripSubexpressionNode(tree)
        return tree

# Condition parser
class SigmaConditionParser:
    """Parser for Sigma condition expression"""
    searchOperators = [     # description of operators: (token id, number of operands, parse tree node class) - order == precedence
            (SigmaConditionToken.TOKEN_ALL, 1, generateAllOf),
            (SigmaConditionToken.TOKEN_ONE, 1, generateOneOf),
            (SigmaConditionToken.TOKEN_ID,  0, convertId),
            (SigmaConditionToken.TOKEN_NOT, 1, ConditionNOT),
            (SigmaConditionToken.TOKEN_AND, 2, ConditionAND),
            (SigmaConditionToken.TOKEN_OR,  2, ConditionOR),
            ]

    def __init__(self, sigmaParser, tokens):
        self.sigmaParser = sigmaParser
        self.config = sigmaParser.config
        self._optimizer = SigmaConditionOptimizer()

        if SigmaConditionToken.TOKEN_PIPE in tokens:    # Condition contains atr least one aggregation expression
            pipepos = tokens.index(SigmaConditionToken.TOKEN_PIPE)
            self.parsedSearch = self.parseSearch(tokens[:pipepos])
            self.parsedAgg = SigmaAggregationParser(tokens[pipepos + 1:], self.sigmaParser, self.config)
        else:
            self.parsedSearch = self.parseSearch(tokens)
            self.parsedAgg = None

    def parseSearch(self, tokens):
        """
        Iterative parsing of search expression.
        """
        def find_close_token_index_in_pairs(tokens, start_index, open_token, close_token):
            """
                the function try to find close_token index for open_token in pairs
                e.g
                    open_token was '(' and
                    tokens were ['(', '...', '(', '...', ')', ')']
                    the first '(' should pair with the last ')' instead of the first ')'
                
                Parameters:
                    tokens: the list of tokens
                    start_index: the start index (included) of the input tokens for finding the close_token
                    open_token: the token that considered as opening token
                    close_token: the token that considered as closing token
                Returns:
                    the index of the close_token in pair with the open_token
                    raise ValueError when there is no close_token in pairs
            """
            open_token_count = 0
            for i in range(start_index, len(tokens)):
                if tokens[i] == open_token:
                    open_token_count += 1
                elif tokens[i] == close_token:
                    if open_token_count == 0:
                        return i
                    else:
                        open_token_count -= 1
            raise ValueError(f"matched close_token {close_token} is not found in tokens")
        # 1. Identify subexpressions with parentheses around them and parse them like a separate search expression
        while SigmaConditionToken.TOKEN_LPAR in tokens:
            lPos = tokens.index(SigmaConditionToken.TOKEN_LPAR)
            lTok = tokens[lPos]
            try:
                rPos = find_close_token_index_in_pairs(tokens, lPos+1, SigmaConditionToken.TOKEN_LPAR, SigmaConditionToken.TOKEN_RPAR)
                rTok = tokens[rPos]
            except ValueError as e:
                raise SigmaParseError("Missing matching closing parentheses") from e
            if lPos + 1 == rPos:
                raise SigmaParseError("Empty subexpression at " + str(lTok.pos))
            if lPos > rPos:
                raise SigmaParseError("Closing parentheses at position " + str(rTok.pos) + " precedes opening at position " + str(lTok.pos))

            subparsed = self.parseSearch(tokens[lPos + 1:rPos])
            tokens = tokens[:lPos] + NodeSubexpression(subparsed) + tokens[rPos + 1:]   # replace parentheses + expression with group node that contains parsed subexpression

        # 2. Iterate over all known operators in given precedence
        for operator in self.searchOperators:
            # 3. reduce all occurrences into corresponding parse tree nodes
            while operator[0] in tokens:
                pos_op = tokens.index(operator[0])
                tok_op = tokens[pos_op]
                if operator[1] == 0:    # operator
                    treenode = operator[2](self.sigmaParser, tok_op)
                    tokens = tokens[:pos_op] + treenode + tokens[pos_op + 1:]
                elif operator[1] == 1:    # operator value
                    pos_val = pos_op + 1
                    tok_val = tokens[pos_val]
                    treenode = operator[2](self.sigmaParser, tok_op, tok_val)
                    tokens = tokens[:pos_op] + treenode + tokens[pos_val + 1:]
                elif operator[1] == 2:    # value1 operator value2
                    pos_val1 = pos_op - 1
                    pos_val2 = pos_op + 1
                    tok_val1 = tokens[pos_val1]
                    tok_val2 = tokens[pos_val2]
                    treenode = operator[2](self.sigmaParser, tok_op, tok_val1, tok_val2)
                    tokens = tokens[:pos_val1] + treenode + tokens[pos_val2 + 1:]

        if len(tokens) != 1:     # parse tree must begin with exactly one node
            raise ValueError("Parse tree must have exactly one start node!")
        query_cond = tokens[0]

        # 4. Integrate conditions from logsources in configurations
        ls_cond = self.sigmaParser.get_logsource_condition()
        if ls_cond is not None:
            cond = ConditionAND()
            cond.add(ls_cond)
            cond.add(query_cond)
            query_cond = cond

        return self._optimizer.optimizeTree(query_cond)

    def __str__(self):  # pragma: no cover
        return str(self.parsedSearch)

    def __len__(self):  # pragma: no cover
        return len(self.parsedSearch)


# Aggregation parser
class SigmaAggregationParser(SimpleParser):
    """Parse Sigma aggregation expression and provide parsed data"""
    parsingrules = [
            {   # State 0
                SigmaConditionToken.TOKEN_AGG:  ("aggfunc", "trans_aggfunc", 1),
                SigmaConditionToken.TOKEN_NEAR: ("aggfunc", "init_near_parsing", 8),
            },
            {   # State 1
                SigmaConditionToken.TOKEN_LPAR: (None, None, 2)
            },
            {   # State 2
                SigmaConditionToken.TOKEN_RPAR: (None, None, 4),
                SigmaConditionToken.TOKEN_ID: ("aggfield", "trans_fieldname", 3),
            },
            {   # State 3
                SigmaConditionToken.TOKEN_RPAR: (None, None, 4)
            },
            {   # State 4
                SigmaConditionToken.TOKEN_BY: ("cond_op", None, 5),
                SigmaConditionToken.TOKEN_EQ: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_LT: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_LTE: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_GT: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_GTE: ("cond_op", None, 7),
            },
            {   # State 5
                SigmaConditionToken.TOKEN_ID: ("groupfield", "trans_fieldname", 6)
            },
            {   # State 6
                SigmaConditionToken.TOKEN_EQ: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_LT: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_LTE: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_GT: ("cond_op", None, 7),
                SigmaConditionToken.TOKEN_GTE: ("cond_op", None, 7),
            },
            {   # State 7
                SigmaConditionToken.TOKEN_ID: ("condition", None, -1)
            },
            {   # State 8
                SigmaConditionToken.TOKEN_ID: (None, "store_search_id", 9)
            },
            {   # State 9
                SigmaConditionToken.TOKEN_AND: (None, "set_include", 10),
            },
            {   # State 10
                SigmaConditionToken.TOKEN_NOT: (None, "set_exclude", 8),
                SigmaConditionToken.TOKEN_ID: (None, "store_search_id", 9),
            },
            ]
    finalstates = {-1, 9}

    # Aggregation functions
    AGGFUNC_COUNT = 1
    AGGFUNC_MIN   = 2
    AGGFUNC_MAX   = 3
    AGGFUNC_AVG   = 4
    AGGFUNC_SUM   = 5
    AGGFUNC_NEAR  = 6
    aggfuncmap = {
            "count": AGGFUNC_COUNT,
            "min":   AGGFUNC_MIN,
            "max":   AGGFUNC_MAX,
            "avg":   AGGFUNC_AVG,
            "sum":   AGGFUNC_SUM,
            "near":  AGGFUNC_NEAR,
            }

    def __init__(self, tokens, parser, config):
        self.parser = parser
        self.config = config
        self.aggfield = None
        self.groupfield = None
        super().__init__(tokens)

    def trans_aggfunc(self, name):
        """Translate aggregation function name into constant"""
        try:
            return self.aggfuncmap[name]
        except KeyError:
            raise SigmaParseError("Unknown aggregation function '%s'" % (name))

    def trans_fieldname(self, fieldname):
        """Translate field name into configured mapped name"""
        mapped = self.config.get_fieldmapping(fieldname).resolve_fieldname(fieldname, self.parser)
        if type(mapped) == str:
            return mapped
        else:
            raise NotImplementedError("Field mappings in aggregations must be single valued")

    def init_near_parsing(self, name):
        """Initialize data structures for 'near" aggregation operator parsing"""
        self.include = list()
        self.exclude = list()
        self.current = self.include
        return self.trans_aggfunc(name)

    def store_search_id(self, name):
        self.current.append(name)
        return name

    def set_include(self, name):
        self.current = self.include

    def set_exclude(self, name):
        self.current = self.exclude
