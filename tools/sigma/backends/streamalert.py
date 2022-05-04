import re
import requests
import json
import os
from sigma.config.eventdict import event
from fnmatch import fnmatch

from sigma.parser.rule import SigmaParser
from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.exceptions import NotSupportedError
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.parser.condition import ConditionOR, ConditionAND, NodeSubexpression

from sigma.parser.modifiers.base import SigmaTypeModifier


class StreamAlertQueryBackend(SingleTextQueryBackend):
    """Converts Sigma rule into StreamAlert code. Not support aggregations. Contributed by AlertIQ."""

    identifier = "streamalert"
    active = True

    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " or "

    valueExpression = '%s'
    valueRawExpression = "record['_raw'].contains(%s)"
    typedValueExpression = {SigmaRegularExpressionModifier: "'%s'"}

    nullExpression = "record.get('%s', None) == None"
    notNullExpression = "record.get('%s', None) != None"
    mapExpression = "record['%s'] == %s"
    endswithExpression = "record['%s'].endswith(%s)"
    startswithExpression = "record['%s'].startswith(%s)"
    containsExpression = "record['%s'].contains(%s)"
    regexExpression = "re.match(%s, record['%s'])"

    mapListsSpecialHandling = False
    escapeCharacters = ['\\', '\'', '\"']
    removeLeadingCharacters = ['*']

    def __init__(self, *args, **kwargs):
        """Initialize field mappings."""
        super().__init__(*args, **kwargs)
        self.excluded_fields = None
        self.is_upper = False
        self.import_libs = ''

    def cleanLeading(self, val: str):
        if val != '*' and any(val.startswith(a) for a in self.removeLeadingCharacters):
            val = val[1:]
        if val != '*' and any(val.endswith(a) for a in self.removeLeadingCharacters):
            val = val[:-1]

        val = val.strip()

        # val = re.sub(r'^\\+', '', val)
        val = re.sub(r'\\+$', '', val)

        if not val.startswith('"'):
            val = '"%s' % re.sub(r'(?<=[^\\])"', '\\"', val)
        if not val.endswith('"') or val == '"' or val.endswith('\\"'):
            val = '%s"' % re.sub(r'(?<=[^\\])"', '\\"', val)

        return val

    def escapeCharacter(self, val):
        for ch in self.escapeCharacters:
            val = val.replace(ch, '\\' + ch)
        return val

    def unescapeCharacter(self, val):
        for ch in self.escapeCharacters:
            val = val.replace('\\' + ch, ch)
        return val

    def cleanWhitespace(self, val):
        val = val.replace('  ', ' ')
        if re.match('\S+ \S', val):
            matches = re.findall('(?:^|\(| )(.+?)(?:\)| or| and|$)', val)
            for strMatch in matches:
                if re.match('\S+ \S', strMatch):
                    strUnescapeMatch = self.unescapeCharacter(strMatch)
                    val = val.replace(strMatch, '{}'.format(strUnescapeMatch))
        return val.strip()

    def cleanValue(self, val):
        if isinstance(val, str):
            val = val.strip()
            val = self.escapeCharacter(val)
            val = self.cleanLeading(val)
            # val = self.cleanWhitespace(val)
        return val

    def cleanIPRange(self, value):
        new_value = value
        if isinstance(new_value, str) and value.find('*'):
            sub = value.count('.')
            if value[-2:] == '.*':
                value = value[:-2]
            min_ip = value + '.0' * (4 - sub)
            new_value = min_ip + '/' + str(8 * (4 - sub))
        elif isinstance(new_value, list):
            for index, vl in enumerate(new_value):
                new_value[index] = self.cleanIPRange(vl)

        return new_value

    def fieldNameMapping(self, fieldname: str, value):
        if fieldname.isupper():
            return fieldname
        new_fieldname = ''
        if self.is_upper:
            for i, a in enumerate(fieldname):
                if a.lower() == 'p' and fieldname[i - 1].lower() == 'i' and i > 0:
                    new_fieldname += a.upper()
                elif a.isupper() and i > 0:
                    new_fieldname += f'_{a}'
                else:
                    new_fieldname += a.upper()

        return new_fieldname if new_fieldname else fieldname

    def mapNode(self, key, value):
        if isinstance(value, str):
            if value != '*' and value.startswith('*') and value.endswith('*'):
                return self.containsExpression % (key, self.cleanValue(value))
            if value.startswith('*') and not value.endswith('*'):
                return self.endswithExpression % (key, self.cleanValue(value))
            if not value.startswith('*') and value.endswith('*'):
                return self.startswithExpression % (key, self.cleanValue(value))

        if isinstance(value, SigmaTypeModifier):
            if isinstance(value, SigmaRegularExpressionModifier):
                self.import_libs += (
                    'import re\n' if 'import re\n' not in self.import_libs else ''
                )
                return self.regexExpression % (self.generateTypedValueNode(value), key)

        return self.mapExpression % (key, self.cleanValue(value))

    def generateValueNode(self, node):
        return (
            self.valueExpression % (str(node))
            if 'record[\'' in str(node)
            else self.valueRawExpression % self.cleanValue(str(node))
        )

    def generateMapItemTypedNode(self, fieldname, value):
        return self.mapExpression % (fieldname, self.generateTypedValueNode(value))

    def generateMapItemNode(self, node):
        fieldname, value = node
        if fieldname.lower() in self.excluded_fields:
            return
        else:
            transformed_fieldname = self.fieldNameMapping(fieldname, value)
            if any(a in transformed_fieldname for a in ["_IP" or "IP_"]):
                value = self.cleanIPRange(value)
            if (
                self.mapListsSpecialHandling == False
                and type(value) in (str, int, list)
            ) or (self.mapListsSpecialHandling == True and type(value) in (str, int)):
                if isinstance(value, list):
                    return self.generateNode(
                        [self.mapNode(transformed_fieldname, a) for a in value]
                    )
                elif isinstance(value, str) or isinstance(value, int):
                    return self.mapNode(transformed_fieldname, value)
            elif type(value) == list:
                return self.generateMapItemListNode(transformed_fieldname, value)
            elif isinstance(value, SigmaTypeModifier):
                return self.mapNode(transformed_fieldname, value)
            elif value is None:
                return self.nullExpression % (transformed_fieldname,)
            else:
                raise TypeError(
                    "Backend does not support map values of type " + str(type(value))
                )

    def generate(self, sigmaparser: SigmaParser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        title = sigmaparser.parsedyaml["title"]

        title_temp = re.sub('\W *', ' ', title).replace('  ', ' ')
        function_name = '_'.join(a.lower() for a in title_temp.split(' '))

        description = sigmaparser.parsedyaml["description"]

        try:
            self.excluded_fields = [
                item.lower()
                for item in sigmaparser.config.config.get("excludedfields", [])
            ]
            service = sigmaparser.parsedyaml['logsource'].get('service', '{service}')
            logsource = ' - '.join(
                '{}:{}'.format(k, v)
                for k, v in sigmaparser.parsedyaml['logsource'].items()
            )
            self.is_upper = 'upper' in sigmaparser.config.config.get("tags", [])
            outputs = sigmaparser.config.config.get("outputs", [])
            publishers = '[{}]'.format(
                ', '.join(sigmaparser.config.config.get("publishers", []))
            )

            self.import_libs = ''
            for publisher in sigmaparser.config.config.get("publishers", []):
                self.import_libs += 'from publishers.general.{0} import {0}\n'.format(
                    publisher
                )
        except KeyError:
            logsource = '{logsource}'
            service = '{service}'

        results = ''
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            result = '''{import_libs}
from streamalert.shared.rule import rule

"""
Title: {title}
Description: {description}
Log Source: {logsource}
"""
@rule(
    logs=['{service}:events'],
    merge_by_keys=['ALERT_NAME'],
    merge_window_mins=5,
    outputs={outputs},
    publishers={publishers}
)
def {function_name}(record):
    return {query}
'''

            if query is not None:
                results += result.format(
                    import_libs=self.import_libs,
                    logsource=logsource,
                    service=service,
                    query=query,
                    title=title,
                    function_name=function_name,
                    description=description,
                    outputs=outputs,
                    publishers=publishers,
                )
        return results
