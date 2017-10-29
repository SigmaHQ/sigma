# Sigma parser

import yaml
import re

COND_NONE = 0
COND_AND  = 1
COND_OR   = 2
COND_NOT  = 3
COND_NULL = 4

class SigmaParser:
    def __init__(self, sigma, config):
        self.definitions = dict()
        self.values = dict()
        self.config = config
        self.parsedyaml = yaml.safe_load(sigma)
        self.parse_sigma()

    def parse_sigma(self):
        try:    # definition uniqueness check
            for definitionName, definition in self.parsedyaml["detection"].items():
                self.definitions[definitionName] = definition
                self.extract_values(definition)     # builds key-values-table in self.values
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

    def parse_definition_byname(self, definitionName, condOverride=None):
        try:
            definition = self.definitions[definitionName]
        except KeyError as e:
            raise SigmaParseError("Unknown definition '%s'" % definitionName) from e
        return self.parse_definition(definition, condOverride)

    def parse_definition(self, definition, condOverride=None):
        if type(definition) not in (dict, list):
            raise SigmaParseError("Expected map or list, got type %s: '%s'" % (type(definition), str(definition)))

        if type(definition) == list:    # list of values or maps
            if condOverride:    # condition given through rule detection condition, e.g. 1 of x
                cond = condOverride()
            else:               # no condition given, use default from spec
                cond = ConditionOR()

            subcond = None
            for value in definition:
                if type(value) in (str, int):
                    cond.add(value)
                elif type(value) in (dict, list):
                    cond.add(self.parse_definition(value))
                else:
                    raise SigmaParseError("Definition list may only contain plain values or maps")
        elif type(definition) == dict:      # map
            cond = ConditionAND()
            for key, value in definition.items():
                mapping = self.config.get_fieldmapping(key)
                if value == None:
                    fields = mapping.resolve_fieldname(key)
                    if type(fields) == str:
                        fields = [ fields ]
                    for field in fields:
                        cond.add(ConditionNULLValue(val=field))
                elif value == "not null":
                    fields = mapping.resolve_fieldname(key)
                    if type(fields) == str:
                        fields = [ fields ]
                    for field in fields:
                        cond.add(ConditionNotNULLValue(val=field))
                else:
                    cond.add(mapping.resolve(key, value, self))

        return cond

    def extract_values(self, definition):
        """Extract all values from map key:value pairs info self.values"""
        if type(definition) == list:     # iterate through items of list
            for item in definition:
                self.extract_values(item)
        elif type(definition) == dict:  # add dict items to map
            for key, value in definition.items():
                self.add_value(key, value)

    def add_value(self, key, value):
        """Add value to values table, create key if it doesn't exist"""
        if key in self.values:
            self.values[key].add(str(value))
        else:
            self.values[key] = { str(value) }

    def get_logsource(self):
        """Returns logsource configuration object for current rule"""
        try:
            ls_rule = self.parsedyaml['logsource']
        except KeyError:
            return None

        try:
            category = ls_rule['category']
        except KeyError:
            category = None
        try:
            product = ls_rule['product']
        except KeyError:
            product = None
        try:
            service = ls_rule['service']
        except KeyError:
            service = None

        return self.config.get_logsource(category, product, service)

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

    def __str__(self):
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
            (SigmaConditionToken.TOKEN_ID,     re.compile("\\w+")),
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

    def __str__(self):
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

class SigmaParseError(Exception):
    pass

### Parse Tree Node Classes ###
class ParseTreeNode:
    """Parse Tree Node Base Class"""
    def __init__(self):
        raise NotImplementedError("ConditionBase is no usable class")

    def __str__(self):
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

# Parse tree converters: convert something into one of the parse tree node classes defined above
def convertAllOf(sigma, op, val):
    """Convert 'all of x' into ConditionAND"""
    return NodeSubexpression(sigma.parse_definition_byname(val.matched, ConditionAND))

def convertOneOf(sigma, op, val):
    """Convert '1 of x' into ConditionOR"""
    return NodeSubexpression(sigma.parse_definition_byname(val.matched, ConditionOR))

def convertId(sigma, op):
    """Convert search identifiers (lists or maps) into condition nodes according to spec defaults"""
    return NodeSubexpression(sigma.parse_definition_byname(op.matched))

# Condition parser class
class SigmaConditionParser:
    """Parser for Sigma condition expression"""
    searchOperators = [     # description of operators: (token id, number of operands, parse tree node class) - order == precedence
            (SigmaConditionToken.TOKEN_ALL, 1, convertAllOf),
            (SigmaConditionToken.TOKEN_ONE, 1, convertOneOf),
            (SigmaConditionToken.TOKEN_ID,  0, convertId),
            (SigmaConditionToken.TOKEN_NOT, 1, ConditionNOT),
            (SigmaConditionToken.TOKEN_AND, 2, ConditionAND),
            (SigmaConditionToken.TOKEN_OR,  2, ConditionOR),
            ]

    def __init__(self, sigmaParser, tokens):
        self.sigmaParser = sigmaParser
        self.config = sigmaParser.config

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
        querycond = tokens[0]

        logsource = self.sigmaParser.get_logsource()
        if logsource != None:
            # 4. Integrate conditions from configuration
            if logsource.conditions != None:
                cond = ConditionAND()
                cond.add(logsource.conditions)
                cond.add(querycond)
                querycond = cond

            # 5. Integrate index conditions if applicable for backend
            indexcond = logsource.get_indexcond()
            if indexcond != None:
                cond = ConditionAND()
                cond.add(indexcond)
                cond.add(querycond)
                querycond = cond

        return querycond

    def __str__(self):
        return str(self.parsedSearch)

    def __len__(self):
        return len(self.parsedSearch)

class SimpleParser:
    """
    Rule-defined parser that converts a token stream into a Python object.

    Rules are defined in the class property parsingrules, a list of dict of tuples with the following format:
    [ { token_0_0: parsing_rule_0_0, token_0_1: parsing_rule_0_1, ..., token_0_n: parsing_rule_0_n } , ... , { token_m_0: parsing_rule_m_0, ... } ]

    Each list index of parsing rules represents a parser state.
    Each parser state is defined by a dict with associates a token with a rule definition.
    The rule definition is a tuple that defines what is done next when the parser encounters a token in the current parser state:

    ( storage attribute, transformation function, next ruleset)

    * storage attribute: the name of the object attribute that is used for storage of the attribute
    * transformation method: name of an object method that is called before storage. It gets a parameter and returns the value that is stored
    * next state: next parser state

    A None value means that the action (transformation, storage or state change) is not conducted.

    A negative state has the special meaning that no further token is expected and may be used as return value.
    The set or list finalstates contains valid final states. The parser verifies after the last token that it
    has reached one of these states. if not, a parse error is raised.
    """

    def __init__(self, tokens, init_state=0):
        self.state = init_state

        for token in tokens:
            if self.state < 0:
                raise SigmaParseError("No further token expected, but read %s" % (str(token)))
            try:
                rule = self.parsingrules[self.state][token.type]
            except KeyError as e:
                raise SigmaParseError("Unexpected token %s at %d in aggregation expression" % (str(token), token.pos)) from e

            value = token.matched
            trans_value = value
            if rule[1] != None:
                trans_value = getattr(self, rule[1])(value)
            if rule[0] != None:
                setattr(self, rule[0], trans_value)
                setattr(self, rule[0] + "_notrans", value)
            if rule[2] != None:
                self.state = rule[2]
        if self.state not in self.finalstates:
            raise SigmaParseError("Unexpected end of aggregation expression, state=%d" % (self.state))

    def __str__(self):
        return "[ Parsed: %s ]" % (" ".join(["%s=%s" % (key, val) for key, val in self.__dict__.items() ]))
 
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
    finalstates = { -1, 9 }

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
        self.aggfield = ""
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
        mapped = self.config.get_fieldmapping(fieldname).resolve_fieldname(fieldname)
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

    def trans_timeframe(self, name):
        return self.parser.parsedyaml["detection"][name]

# Field Mapping Definitions
def FieldMapping(source, target=None):
    """Determines target type and instantiate appropriate mapping type"""
    if target == None:
        return SimpleFieldMapping(source, source)
    elif type(target) == str:
        return SimpleFieldMapping(source, target)
    elif type(target) == list:
        return MultiFieldMapping(source, target)
    elif type(target) == dict:
        return ConditionalFieldMapping(source, target)

class SimpleFieldMapping:
    """1:1 field mapping"""
    target_type = str

    def __init__(self, source, target):
        """Initialization with generic target type check"""
        if type(target) != self.target_type:
            raise TypeError("Target type mismatch: wrong mapping type for this target")
        self.source = source
        self.target = target

    def resolve(self, key, value, sigmaparser):
        """Return mapped field name"""
        return (self.target, value)

    def resolve_fieldname(self, fieldname):
        return self.target

class MultiFieldMapping(SimpleFieldMapping):
    """1:n field mapping that expands target field names into OR conditions"""
    target_type = list

    def resolve(self, key, value, sigmaparser):
        """Returns multiple target field names as OR condition"""
        cond = ConditionOR()
        for fieldname in self.target:
            cond.add((fieldname, value))
        return cond

    def resolve_fieldname(self, fieldname):
        return self.target

class ConditionalFieldMapping(SimpleFieldMapping):
    """
    Conditional field mapping:
    * key contains field=value condition, value target mapping
    * key "default" maps when no condition matches
    * if no condition matches and there is no default, don't perform mapping
    """
    target_type = dict

    def __init__(self, source, target):
        """Init table between condition field names and values"""
        super().__init__(source, target)
        self.conditions = dict()    # condition field -> condition value -> target fields
        self.default = None
        for condition, target in self.target.items():
            try:                    # key contains condition (field=value)
                field, value = condition.split("=")
                self.add_condition(field, value, target)
            except ValueError as e:      # no, condition - "default" expected
                if condition == "default":
                    if self.default == None:
                        if type(target) == str:
                            self.default = [ target ]
                        elif type(target) == list:
                            self.default = target
                        else:
                            raise SigmaConfigParseError("Default mapping must be single value or list")
                    else:
                        raise SigmaConfigParseError("Conditional field mapping can have only one default value, use list for multiple target mappings")
                else:
                    raise SigmaConfigParseError("Expected condition or default") from e

    def add_condition(self, field, value, target):
        if field not in self.conditions:
            self.conditions[field] = dict()
        if value not in self.conditions[field]:
            self.conditions[field][value] = list()
        if type(target) == str:
            self.conditions[field][value].append(target)
        elif type(target) == list:
            self.conditions[field][value].extend(target)

    def resolve(self, key, value, sigmaparser):
        # build list of matching target mappings
        targets = set()
        for condfield in self.conditions:
            if condfield in sigmaparser.values:
                rulefieldvalues = sigmaparser.values[condfield]
                for condvalue in self.conditions[condfield]:
                    if condvalue in rulefieldvalues:
                        targets.update(self.conditions[condfield][condvalue])
        if len(targets) == 0:       # no matching condition, try with default mapping
            if self.default != None:
                targets = self.default

        if len(targets) == 1:     # result set contains only one target, return mapped item (like SimpleFieldMapping)
            return (targets.pop(), value)
        elif len(targets) > 1:        # result set contains multiple targets, return all linked as OR condition (like MultiFieldMapping)
            cond = ConditionOR()
            for target in targets:
                cond.add((target, value))
            return cond
        else:                       # no mapping found
            return (key, value)

    def resolve_fieldname(self, fieldname):
        if self.default != None:
            return self.default
        else:
            return fieldname

# Configuration
class SigmaConfiguration:
    """Sigma converter configuration. Contains field mappings and logsource descriptions"""
    def __init__(self, configyaml=None):
        if configyaml == None:
            self.config = None
            self.fieldmappings = dict()
            self.logsources = dict()
            self.logsourcemerging = SigmaLogsourceConfiguration.MM_AND
            self.defaultindex = None
            self.backend = None
        else:
            config = yaml.safe_load(configyaml)
            self.config = config

            self.fieldmappings = dict()
            try:
                for source, target in config['fieldmappings'].items():
                    self.fieldmappings[source] = FieldMapping(source, target)
            except KeyError:
                pass
            if type(self.fieldmappings) != dict:
                raise SigmaConfigParseError("Fieldmappings must be a map")

            try:
                self.logsourcemerging = config['logsourcemerging']
            except KeyError:
                self.logsourcemerging = SigmaLogsourceConfiguration.MM_AND

            try:
                self.defaultindex = config['defaultindex']
            except KeyError:
                self.defaultindex = None

            self.logsources = list()
            self.backend = None

    def get_fieldmapping(self, fieldname):
        """Return mapped fieldname if mapping defined or field name given in parameter value"""
        try:
            return self.fieldmappings[fieldname]
        except KeyError:
            return FieldMapping(fieldname)

    def get_logsource(self, category, product, service):
        """Return merged log source definition of all logosurces that match criteria"""
        matching = [logsource for logsource in self.logsources if logsource.matches(category, product, service)]
        return SigmaLogsourceConfiguration(matching, self.defaultindex)

    def set_backend(self, backend):
        """Set backend. This is used by other code to determine target properties for index addressing"""
        self.backend = backend
        if self.config != None:
            if 'logsources' in self.config:
                logsources = self.config['logsources']
                if type(logsources) != dict:
                    raise SigmaConfigParseError("Logsources must be a map")
                for name, logsource in logsources.items():
                    self.logsources.append(SigmaLogsourceConfiguration(logsource, self.defaultindex, name, self.logsourcemerging, self.get_indexfield()))

    def get_indexfield(self):
        """Get index condition if index field name is configured"""
        if self.backend != None:
            return self.backend.index_field

class SigmaLogsourceConfiguration:
    """Contains the definition of a log source"""
    MM_AND = "and"  # Merge all conditions with AND
    MM_OR  = "or"   # Merge all conditions with OR

    def __init__(self, logsource=None, defaultindex=None, name=None, mergemethod=MM_AND, indexfield=None):
        self.name = name
        self.indexfield = indexfield
        if logsource == None:               # create empty object
            self.category = None
            self.product = None
            self.service = None
            self.index = list()
            self.conditions = None
        elif type(logsource) == list and all([isinstance(o, SigmaLogsourceConfiguration) for o in logsource]):      # list of SigmaLogsourceConfigurations: merge according to mergemethod
            # Merge category, product and service
            categories = set([ ls.category for ls in logsource if ls.category != None ])
            products = set([ ls.product for ls in logsource if ls.product != None ])
            services = set([ ls.service for ls in logsource if ls.service != None])
            if len(categories) > 1 or len(products) > 1 or len(services) > 1:
                raise ValueError("Merged SigmaLogsourceConfigurations must have disjunct categories (%s), products (%s) and services (%s)" % (str(categories), str(products), str(services)))

            try:
                self.category = categories.pop()
            except KeyError:
                self.category = None
            try:
                self.product = products.pop()
            except KeyError:
                self.product = None
            try:
                self.service = services.pop()
            except KeyError:
                self.service = None

            # Merge all index patterns
            self.index = list(set([index for ls in logsource for index in ls.index]))       # unique(flat(logsources.index))
            if len(self.index) == 0 and defaultindex is not None:   # if no index pattern matched and default index is present: use default index
                if type(defaultindex) == str:
                    self.index = [defaultindex]
                elif type(defaultindex) == list and all([type(i) == str for i in defaultindex]):
                    self.index = defaultindex
                else:
                    raise TypeError("Default index must be string or list of strings")

            # "merge" index field (should never differ between instances because it is provided by backend class
            indexfields = [ ls.indexfield for ls in logsource if ls.indexfield != None ]
            try:
                self.indexfield = indexfields[0]
            except IndexError:
                self.indexfield = None

            # Merge conditions according to mergemethod
            if mergemethod == self.MM_AND:
                cond = ConditionAND()
            elif mergemethod == self.MM_OR:
                cond = ConditionOR()
            else:
                raise ValueError("Mergemethod must be '%s' or '%s'" % (self.MM_AND, self.MM_OR))
            for ls in logsource:
                if ls.conditions != None:
                    cond.add(ls.conditions)
            if len(cond) > 0:
                self.conditions = cond
            else:
                self.conditions = None
        elif type(logsource) == dict:       # create logsource configuration from parsed yaml
            if 'category' in logsource and type(logsource['category']) != str \
                    or 'product' in logsource and type(logsource['product']) != str \
                    or 'service' in logsource and type(logsource['service']) != str:
                raise SigmaConfigParseError("Logsource category, product or service must be a string")
            try:
                self.category = logsource['category']
            except KeyError:
                self.category = None
            try:
                self.product = logsource['product']
            except KeyError:
                self.product = None
            try:
                self.service = logsource['service']
            except KeyError:
                self.service = None
            if self.category == None and self.product == None and self.service == None:
                raise SigmaConfigParseError("Log source definition will not match")

            if 'index' in logsource:
                index = logsource['index']
                if type(index) not in (str, list):
                    raise SigmaConfigParseError("Logsource index must be string or list of strings")
                if type(index) == list and not all([type(index) == str for index in logsource['index']]):
                    raise SigmaConfigParseError("Logsource index patterns must be strings")
                if type(index) == list:
                    self.index = index
                else:
                    self.index = [ index ]
            else:
                # no default index handling here - this branch is executed if log source definitions are parsed from
                # config and these must not necessarily contain an index definition. A valid index may later be result
                # from a merge, where default index handling applies.
                self.index = []

            if 'conditions' in logsource:
                if type(logsource['conditions']) != dict:
                    raise SigmaConfigParseError("Logsource conditions must be a map")
                cond = ConditionAND()
                for key, value in logsource['conditions'].items():
                    cond.add((key, value))
                self.conditions = cond
            else:
                self.conditions = None
        else:
            raise SigmaConfigParseError("Logsource definitions must be maps")

    def matches(self, category, product, service):
        """Match log source definition against given criteria, None = ignore"""
        searched = 0
        for searchval, selfval in zip((category, product, service), (self.category, self.product, self.service)):
            if searchval == None and selfval != None:
                return False
            if selfval != None:
                searched += 1
                if searchval != selfval:
                    return False
        if searched:
            return True

    def get_indexcond(self):
        """Get index condition if index field name is configured"""
        cond = ConditionOR()
        if self.indexfield:
            for index in self.index:
                cond.add((self.indexfield, index))
            return cond
        else:
            return None

    def __str__(self):
        return "[ LogSourceConfiguration: %s %s %s indices: %s ]" % (self.category, self.product, self.service, str(self.index))

class SigmaConfigParseError(Exception):
    pass
