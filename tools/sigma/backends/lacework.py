# Output backends for sigmac
# Copyright 2021 Lacework, Inc.
# Authors:
# David Hazekamp (david.hazekamp@lacework.net)
# Rachel Rice (rachel.rice@lacework.net)

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

import json
import re
import textwrap
import yaml

from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.exceptions import BackendError
from sigma.parser.modifiers.base import SigmaTypeModifier


LACEWORK_CONFIG = yaml.load(
    textwrap.dedent('''
    ---
    version: 0.1
    services:
      cloudtrail:
        evaluatorId: Cloudtrail
        source: CloudTrailRawEvents
        fieldMap:
          - sigmaField: eventName
            laceworkField: EVENT_NAME
            matchType: exact
            continue: false
          - sigmaField: eventSource
            laceworkField: EVENT_SOURCE
            matchType: exact
            continue: false
          - sigmaField: errorCode
            laceworkField: ERROR_CODE
            matchType: exact
            continue: false
          - sigmaField: "^(.*)$"
            laceworkField: EVENT:$1
            matchType: regex
            continue: true
          - sigmaField: "^(.*?)\\\\.type$"
            laceworkField: '$1."type"'
            matchType: regex
            continue: true
        returns:
          - INSERT_ID
          - INSERT_TIME
          - EVENT_TIME
          - EVENT
        alertProfile: LW_CloudTrail_Alerts
    '''),
    Loader=yaml.SafeLoader
)


def safe_get(obj, name, inst):
    """
    Sweet helper for getting objects
    """
    try:
        assert isinstance(obj[name], inst)
        value = obj[name]
    except Exception:
        value = inst()

    return value


def get_output_format(config):
    return (
        'json'
        if (
            safe_get(config, 'json', bool)
            or safe_get(config, 'JSON', bool)
        )
        else 'yaml'
    )


# YAML Tools
def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, str_presenter)


class LaceworkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Lacework Policy Platform"""
    identifier = "lacework"
    active = True
    # our approach to config will be such that we support both an
    # embedded or specified config.
    config_required = False

    andToken = ' and '
    orToken = ' or '
    notToken = 'not '
    subExpression = '(%s)'
    listExpression = 'in (%s)'
    listSeparator = ', '
    valueExpression = "'%s'"
    nullExpression = '%s is null'
    notNullExpression = '%s is not null'
    mapExpression = '%s = %s'
    mapListsSpecialHandling = True
    mapListValueExpression = '%s %s'

    def generate(self, sigmaparser):
        """
        Method is called for each sigma rule and receives the parsed rule (SigmaParser)
        """
        # 1. get embedded config global
        config = LACEWORK_CONFIG

        # 2. overlay backend options
        config.update(self.backend_options)

        # 3. set a class instance variable for sigma fields
        self.laceworkSigmaFields = LaceworkQuery.get_fields(sigmaparser)

        # 4. set a class instance variable for lacework field mapping
        self.laceworkFieldMap = LaceworkQuery.get_field_map(LACEWORK_CONFIG, sigmaparser)

        # 5. get output format
        output_format = get_output_format(config)

        # determine if we're generating query/policy/both
        result = ''
        if LaceworkQuery.should_generate_query(config):
            query = LaceworkQuery(
                config, sigmaparser, self, output_format=output_format)
            result += str(query)
        if LaceworkPolicy.should_generate_policy(config):
            policy = LaceworkPolicy(
                config, sigmaparser, output_format=output_format)

            # if we're in json mode and have already generated a query
            # add a newline before emitting policy
            if result and output_format == 'json':
                result += '\n'

            result += str(policy)

        return result

    def generateValueNode(self, node):
        """
        Value Expression for Lacework Query Language (LQL)

        If value is a field name
        1.  Do not wrap in valueExpression
        2.  Transform using fieldNameMapping()
        """
        node = self.cleanValue(str(node))

        if node in self.laceworkSigmaFields:
            return self.fieldNameMapping(node, None)
        return self.valueExpression % node

    def generateMapItemNode(self, node):
        """
        Map Expression for Lacework Query Language (LQL)

        Special handling for contains by inspecting value for wildcards
        """
        fieldname, value = node

        transformed_fieldname = self.fieldNameMapping(fieldname, value)

        # is not null
        if value == '*':
            return f'{transformed_fieldname} is not null'
        # contains
        if (
            isinstance(value, str)
            and value.startswith('*')
            and value.endswith('*')
        ):
            value = self.generateValueNode(value[1:-1])
            return f"contains({transformed_fieldname}, {value})"
        # startswith
        if (
            isinstance(value, str)
            and value.endswith('*')  # a wildcard at the end signifies startswith
        ):
            value = self.generateValueNode(value[:-1])
            return f"starts_with({transformed_fieldname}, {value})"
        # endswith
        if (
            isinstance(value, str)
            and value.startswith('*')  # a wildcard at the start signifies endswith
        ):
            new_value = self.generateValueNode(value[1:])
            if new_value != (self.valueExpression % value[1:]):
                raise BackendError(
                    'Lacework backend only supports endswith for literal string values')
            return f"{transformed_fieldname} <> {new_value}"
        if (
            self.mapListsSpecialHandling is False and isinstance(value, (str, int, list))
            or self.mapListsSpecialHandling is True and isinstance(value, (str, int))
        ):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError(
                f'Lacework backend does not support map values of type {type(value)}')

    def fieldNameMapping(self, fieldname, value):
        """
        Field Name Mapping for Lacework Query Language (LQL)

        The Lacework backend is not using a traditional config.
        As such we map field names here using our custom backend config.
        """
        if not (isinstance(fieldname, str) and fieldname):
            return fieldname

        for map in self.laceworkFieldMap:
            if not isinstance(map, dict):
                continue

            sigma_field = safe_get(map, 'sigmaField', str)
            if not sigma_field:
                continue

            lacework_field = safe_get(map, 'laceworkField', str)
            if not lacework_field:
                continue

            continyu = safe_get(map, 'continue', bool)

            # exact
            if (
                map.get('matchType') == 'exact'
                and sigma_field == fieldname
            ):
                fieldname = lacework_field
                if not continyu:
                    return fieldname

            # startswith
            if (
                map.get('matchType') == 'startswith'
                and fieldname.startswith(sigma_field)
            ):
                fieldname = f'{lacework_field}{fieldname[len(sigma_field):]}'
                if not continyu:
                    return fieldname

            # regex
            if map.get('matchType') == 'regex':
                fieldname_re = re.compile(sigma_field)
                fieldname_match = fieldname_re.match(fieldname)

                if not fieldname_match:
                    continue

                for i, group in enumerate(fieldname_match.groups(), start=1):
                    if group is None:
                        continue
                    fieldname = lacework_field.replace(f'${i}', group)

                if not continyu:
                    return fieldname

        return fieldname


class LaceworkQuery:
    def __init__(
        self,
        config,
        sigmaparser,
        backend,
        output_format='yaml'
    ):
        rule = sigmaparser.parsedyaml
        conditions = sigmaparser.condparsed

        # 0. Get Output Format
        self.output_format = str(output_format).lower()

        # 1. Get Service
        self.service_name = self.get_service(rule)

        # 2. Get Service Config
        self.service_config = self.get_service_config(
            config, self.service_name)

        # 3. Get Evaluator ID
        self.evaluator_id = self.get_evaluator_id(
            self.service_name, self.service_config)

        # 4. Get Query ID
        self.title, self.query_id = self.get_query_id(rule)

        # 5. Get Query Source
        self.query_source = self.get_query_source(
            self.service_name, self.service_config)

        # 6. Get Query Returns
        self.returns = self.get_query_returns(
            self.service_name, self.service_config)

        # 7. Get Query Text
        self.query_text = self.get_query_text(backend, conditions)

    def get_query_text(self, backend, conditions):
        query_template = (
            '{id} {{\n'
            '    {source_block}\n'
            '    {filter}\n'
            '    {return_block}\n'
            '}}'
        )

        # 1. get_query_source_block
        source_block = self.get_query_source_block()

        # 2. get_query_filters
        filter_block = self.get_query_filter_block(backend, conditions)

        # 3. get_query_returns
        return_block = self.get_query_return_block()

        return query_template.format(
            id=self.query_id,
            source_block=source_block,
            filter=filter_block,
            return_block=return_block
        )

    def get_query_source_block(self):
        source_block_template = (
            'source {{\n'
            '        {source}\n'
            '    }}'
        )
        return source_block_template.format(
            source=self.query_source
        )

    def get_query_return_block(self):
        return_block_template = (
            'return distinct {{\n'
            '{returns}\n'
            '    }}'
        )
        return return_block_template.format(
            returns=',\n'.join(f'        {r}' for r in self.returns)
        )

    def __iter__(self):
        for key, attr in {
            'evaluatorId': 'evaluator_id',
            'queryId': 'query_id',
            'queryText': 'query_text'
        }.items():
            yield (key, getattr(self, attr))

    def __str__(self):
        o = dict(self)

        if self.output_format == 'json':
            return json.dumps(o, indent=4)

        return yaml.dump(
            o,
            explicit_start=True,
            default_flow_style=False,
            sort_keys=False
        )

    @staticmethod
    def get_fields(sigmaparser):
        return safe_get(sigmaparser.parsedyaml, 'fields', list)

    @staticmethod
    def get_field_map(config, sigmaparser):
        config = safe_get(config, 'services', dict)
        service = LaceworkQuery.get_service(sigmaparser.parsedyaml)
        service_config = safe_get(config, service, dict)

        return safe_get(service_config, 'fieldMap', list)

    @staticmethod
    def should_generate_query(backend_options):
        # if we are explicitly requesting a query
        if (
            'query' in backend_options
            and backend_options['query'] is True
        ):
            return True
        # if we are explicitly requesting a policy
        if (
            'policy' in backend_options
            and backend_options['policy'] is True
        ):
            return False
        # we're not being explicit about anything
        return True

    @staticmethod
    def get_service(rule):
        logsource = safe_get(rule, 'logsource', dict)
        return logsource.get('service') or 'unknown'

    @staticmethod
    def get_service_config(config, service):
        config = safe_get(config, 'services', dict)
        service_config = safe_get(config, service, dict)

        # 1. validate logsource service
        if not service_config:
            raise BackendError(
                f'Service {service} is not supported by the Lacework backend')

        return service_config

    @staticmethod
    def get_evaluator_id(service_name, service_config):
        # 3. validate service has an evaluatorId mapping
        evaluator_id = safe_get(service_config, 'evaluatorId', str)

        if not evaluator_id:
            raise BackendError(
                f'Lacework backend could not determine evaluatorId for service {service_name}')

        return evaluator_id

    @staticmethod
    def get_query_id(rule):
        title = safe_get(rule, 'title', str) or 'Unknown'
        # TODO: might need to replace additional non-word characters
        query_id = f'Sigma_{title}'.replace(" ", "_").replace("/", "_Or_")

        return title, query_id

    @staticmethod
    def get_query_source(service_name, service_config):
        # 4. validate service has a source mapping
        source = safe_get(service_config, 'source', str)

        if not source:
            raise BackendError(
                f'Lacework backend could not determine source for service {service_name}')

        return source

    @staticmethod
    def get_query_returns(service_name, service_config):
        returns = safe_get(service_config, 'returns', list)

        if not returns:
            raise BackendError(
                f'Lacework backend could not determine returns for service {service_name}')

        return returns

    @staticmethod
    def get_query_filter_block(backend, conditions):
        filter_block_template = (
            'filter {{\n'
            '        {filter}\n'
            '    }}'
        )

        for parsed in conditions:
            query = backend.generateQuery(parsed)
            before = backend.generateBefore(parsed)
            after = backend.generateAfter(parsed)

            filter = ""
            if before is not None:
                filter = before
            if query is not None:
                filter += query
            if after is not None:
                filter += after

            return filter_block_template.format(filter=filter)


class LaceworkPolicy:
    def __init__(
        self,
        config,
        sigmaparser,
        output_format='yaml'
    ):
        rule = sigmaparser.parsedyaml

        # 0. Get Output Format
        self.output_format = str(output_format).lower()

        # 1. Get Service Name
        self.service_name = LaceworkQuery.get_service(rule)

        # 2. Get Service Config
        self.service_config = LaceworkQuery.get_service_config(
            config, self.service_name)

        # 3. Get Evaluator Id
        self.evaluator_id = LaceworkQuery.get_evaluator_id(
            self.service_name, self.service_config)

        # 4. Get Title
        # 5. Get Query ID
        self.title, self.query_id = LaceworkQuery.get_query_id(rule)

        # 6. Get Enabled
        self.enabled = False

        # 7. Get Policy Type
        self.policy_type = 'Violation'

        # 8. Get Alert Enabled
        self.alert_enabled = False

        # 9. Get Alert Profile
        self.alert_profile = self.get_alert_profile(
            self.service_name, self.service_config)

        # 10. Get Eval Frequency
        self.eval_frequency = 'Hourly'

        # 11. Get Limit
        self.limit = 1000

        # 12. Get Severity
        self.severity = safe_get(rule, 'level', str) or 'medium'

        # 13. Get Description
        self.description = safe_get(rule, 'description', str)

        # 14. Get Remediation
        self.remediation = 'Remediation steps are not represented in Sigma rule specification'

    def __iter__(self):
        for key, attr in {
            'evaluatorId': 'evaluator_id',
            'title': 'title',
            'enabled': 'enabled',
            'policyType': 'policy_type',
            'alertEnabled': 'alert_enabled',
            'alertProfile': 'alert_profile',
            'evalFrequency': 'eval_frequency',
            'queryId': 'query_id',
            'limit': 'limit',
            'severity': 'severity',
            'description': 'description',
            'remediation': 'remediation'
        }.items():
            yield (key, getattr(self, attr))

    def __str__(self):
        o = dict(self)

        if self.output_format == 'json':
            return json.dumps(o, indent=4)

        return yaml.dump(
            o,
            explicit_start=True,
            default_flow_style=False,
            sort_keys=False
        )

    @staticmethod
    def should_generate_policy(backend_options):
        # if we are explicitly requesting a query
        if (
            'policy' in backend_options
            and backend_options['policy'] is True
        ):
            return True
        # if we are explicitly requesting a policy
        if (
            'query' in backend_options
            and backend_options['query'] is True
        ):
            return False
        # we're not being explicit about anything
        return True

    @staticmethod
    def get_alert_profile(service_name, service_config):
        alert_profile = safe_get(service_config, 'alertProfile', str)

        if not alert_profile:
            raise BackendError(
                f'Lacework backend could not determine alert profile for service {service_name}')

        return alert_profile
