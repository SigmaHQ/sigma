# Sigma parser

import yaml
import re

COND_NONE = 0
COND_AND  = 1
COND_OR   = 2
COND_NOT  = 3

class SigmaParser:
    def __init__(self, sigma, config):
        self.definitions = dict()
        self.values = dict()
        self.parsedyaml = yaml.safe_load(sigma)
        self.config = config

    def parse_sigma(self):
        try:    # definition uniqueness check
            for definitionName, definition in self.parsedyaml["detection"].items():
                if definitionName in self.definitions:
                    raise SigmaParseError("Definition '%s' was already defined" % (definitionName))
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
            raise SigmaParseError("Unknown definition '%s'" % (definitionName)) from e
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
            self.values[key].append(value)
        else:
            self.values[key] = [ value ]

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
                    raise SigmaParseError("Unexpected token in condition at position %d")
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
            raise ValueError("Only one element allowed in NOT condition")

    @property
    def item(self):
        try:
            return self.items[0]
        except IndexError:
            return None

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
        if SigmaConditionToken.TOKEN_PIPE in tokens:    # aggregations are not yet supported
            raise NotImplementedError("Aggregation expressions are not yet supported")

        self.sigmaParser = sigmaParser
        self.config = sigmaParser.config
        self.parsedSearch = self.parseSearch(tokens)

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

    def getParseTree(self):
        return(self.parsedSearch)

# Field Mapping Definitions
def FieldMapping(source, target=None):
    """Determines target type and instantiate appropriate mapping type"""
    if target == None:
        return SimpleFieldMapping(source, source)
    elif type(target) == str:
        return SimpleFieldMapping(source, target)
    elif type(target) == list:
        return MultiFieldMapping(source, target)

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

class MultiFieldMapping(SimpleFieldMapping):
    """1:n field mapping that expands target field names into OR conditions"""
    target_type = list

    def resolve(self, key, value, sigmaparser):
        """Returns multiple target field names as OR condition"""
        cond = ConditionOR()
        for fieldname in self.target:
            cond.add((fieldname, value))
        return cond

# Configuration
class SigmaConfiguration:
    """Sigma converter configuration. Contains field mappings and logsource descriptions"""
    def __init__(self, configyaml=None):
        if configyaml == None:
            self.config = None
            self.fieldmappings = dict()
            self.logsources = dict()
            self.logsourcemerging = SigmaLogsourceConfiguration.MM_AND
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
        return SigmaLogsourceConfiguration(matching)

    def set_backend(self, backend):
        """Set backend. This is used by other code to determine target properties for index addressing"""
        self.backend = backend
        if self.config != None:
            if 'logsources' in self.config:
                logsources = self.config['logsources']
                if type(logsources) != dict:
                    raise SigmaConfigParseError("Logsources must be a map")
                for name, logsource in logsources.items():
                    self.logsources.append(SigmaLogsourceConfiguration(logsource, name, self.logsourcemerging, self.get_indexfield()))

    def get_indexfield(self):
        """Get index condition if index field name is configured"""
        if self.backend != None:
            return self.backend.index_field

class SigmaLogsourceConfiguration:
    """Contains the definition of a log source"""
    MM_AND = "and"  # Merge all conditions with AND
    MM_OR  = "or"   # Merge all conditions with OR

    def __init__(self, logsource=None, name=None, mergemethod=MM_AND, indexfield=None):
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
                raise ValueError("Merged SigmaLogsourceConfigurations must have disjunct categories, products and services")

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
                if type(index) == list and not set([type(index) for index in logsource['index']]).issubset({str}):
                    raise SigmaConfigParseError("Logsource index patterns must be strings")
                if type(index) == list:
                    self.index = index
                else:
                    self.index = [ index ]
            else:
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
            if searchval != None and selfval != None:
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
