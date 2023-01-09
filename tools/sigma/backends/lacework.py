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

import sigma

from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.exceptions import BackendError
from sigma.parser.condition import NodeSubexpression, ConditionOR
from sigma.parser.modifiers.base import SigmaTypeModifier


LACEWORK_CONFIG = yaml.load(
    textwrap.dedent('''
    ---
    version: 0.4
    services:
      cloudtrail:
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
    product.categories:
      linux.file_create:
        sources:
          - LW_HE_FILES
        conditions:
          # evaluated hourly and file create time within the last hour
          - and diff_minutes(FILE_CREATED_TIME, current_timestamp_sec()::timestamp) <= 60
        fieldMap:
          - sigmaField: TargetFilename
            laceworkField: PATH
            matchType: exact
        returns:
          - RECORD_CREATED_TIME
          - MID
          - PATH
          - FILE_TYPE
          - SIZE
          - FILEDATA_HASH
          - OWNER_UID
          - OWNER_USERNAME
          - FILE_CREATED_TIME
        alertProfile: LW_HE_FILES_DEFAULT_PROFILE.HE_File_NewViolation
      linux.network_connection:
        sources:
          - LW_HA_CONNECTION_SUMMARY as HACM
          - array_to_rows(ENDPOINT_DETAILS) as (EP_PA)
        fieldMap:
          - sigmaField: Image
            laceworkField: EXE_PATH
            matchType: exact
            action: selfjoin
            selfJoinFilter: HACM.SRC_ENTITY_TYPE = 'Process' AND (HACM.SRC_ENTITY_ID:mid::NUMBER, HACM.SRC_ENTITY_ID:pid_hash::NUMBER) IN { source { LW_HE_PROCESSES AS HEP } filter { EXE_PATH like '%/bin/bash' } return { HEP.MID, HEP.PID_HASH }}
          - sigmaField: DestinationIp
            laceworkField: EP_PA:dst_ip_addr
            matchType: exact
          - sigmaField: DestinationHostname
            laceworkField:
            matchType: exact
            action: raise
        returns:
          - HACM.BATCH_END_TIME
          - HACM.BATCH_START_TIME
          - HACM.DST_ENTITY_ID
          - HACM.DST_ENTITY_TYPE
          - HACM.DST_IN_BYTES
          - HACM.DST_OUT_BYTES
          - HACM.ENDPOINT_DETAILS
          - HACM.NUM_CONNS
          - HACM.SRC_ENTITY_ID
          - HACM.SRC_ENTITY_TYPE
          - HACM.SRC_IN_BYTES
          - HACM.SRC_OUT_BYTES
        alertProfile: LW_HA_CONNECTION_SUMMARY_DEFAULT_PROFILE.HA_Connection_Violation
      linux.process_creation:
        sources:
          - LW_HE_PROCESSES
        conditions:
          # evaluated hourly and file create time within the last hour
          - and diff_minutes(PROCESS_START_TIME, current_timestamp_sec()::timestamp) <= 60
        fieldMap:
          - sigmaField: ParentImage
            laceworkField: EXE_PATH
            matchType: exact
            action: selfjoin
            selfJoinFilter: (MID, PPID_HASH) IN { source { LW_HE_PROCESSES } filter { $query$ } return { MID, PID_HASH } }
          - sigmaField: Image
            laceworkField: EXE_PATH
            matchType: exact
          - sigmaField: ParentCommandLine
            laceworkField: CMDLINE
            matchType: exact
            action: selfjoin
            selfJoinFilter: (MID, PPID_HASH) IN { source { LW_HE_PROCESSES } filter { $query$ } return { MID, PID_HASH } }
          - sigmaField: CommandLine
            laceworkField: CMDLINE
            matchType: exact
          - sigmaField: CurrentDirectory
            laceworkField: CWD
            matchType: exact
          - sigmaField: LogonId
            laceworkField:
            matchType: exact
            action: ignore
          - sigmaField: User
            laceworkField: USERNAME
            matchType: exact
        returns:
          - RECORD_CREATED_TIME
          - MID
          - PID
          - EXE_PATH
          - CMDLINE
          - CWD
          - ROOT
          - USERNAME
          - PROCESS_START_TIME
        alertProfile: LW_HE_PROCESSES_DEFAULT_PROFILE.HE_Process_NewViolation
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


def none_representer(dumper, _):
    return dumper.represent_scalar(u'tag:yaml.org,2002:null', '')


yaml.add_representer(str, str_presenter)
yaml.add_representer(type(None), none_representer)


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
    mapListValueExpression = '%s %s'
    reEscape = re.compile("(')")

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

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.applyOverrides(self.generateANDNode(node))
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.applyOverrides(self.generateORNode(node))
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.applyOverrides(self.generateNOTNode(node))
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.applyOverrides(self.generateNULLValueNode(node))
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.applyOverrides(self.generateNotNULLValueNode(node))
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.applyOverrides(self.generateSubexpressionNode(node))
        elif type(node) == tuple:
            return self.applySelfJoinFilter(node, self.applyOverrides(self.generateMapItemNode(node)))
        elif type(node) in (str, int):
            return self.applyOverrides(self.generateValueNode(node))
        elif type(node) == list:
            return self.applyOverrides(self.generateListNode(node))
        elif isinstance(node, SigmaTypeModifier):
            return self.applyOverrides(self.generateTypedValueNode(node))
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def applySelfJoinFilter(self, node, query):
        if type(node) != tuple:
            raise NotImplementedError('selfJoinFilter is not wired up for node type %s' % (str(type(node))))
        fieldname, value = node

        sjf = self._get_self_join_filter(fieldname)
        if not sjf:
            return query
        return sjf.replace('$query$', query)

    def generateValueNode(self, node):
        """
        Value Expression for Lacework Query Language (LQL)

        If value is a field name
        1.  Do not wrap in valueExpression
        2.  Transform using fieldNameMapping()
        """
        node = self.cleanValue(str(node).strip())

        if node in self.laceworkSigmaFields:
            if self._should_ignore_field(node):
                return None
            return self.fieldNameMapping(node, None)
        return self.valueExpression % node

    def generateMapItemNode(self, node):
        """
        Map Expression for Lacework Query Language (LQL)

        Special handling for contains by inspecting value for wildcards
        """
        fieldname, value = node

        if self._should_ignore_field(fieldname):
            return None
        transformed_fieldname = self.fieldNameMapping(fieldname, value)

        # is not null
        if value == '*':
            if ':' in transformed_fieldname:
                return f'value_exists({transformed_fieldname})'
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
            value = f'%{value[1:]}'
            new_value = self.generateValueNode(value)
            if new_value != (self.valueExpression % value):
                raise BackendError(
                    'Lacework backend only supports endswith for literal string values')
            return f"{transformed_fieldname} LIKE {new_value}"
        if isinstance(value, (str, int)):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        # mapListsHandling
        elif type(value) == list:
            # if a list contains values with wildcards we can't use standard handling ("in")
            if any([x for x in value if x.startswith('*') or x.endswith('*')]):
                node = NodeSubexpression(
                    ConditionOR(None, None, *[(transformed_fieldname, x) for x in value])
                )
                return self.generateNode(node)
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError(
                f'Lacework backend does not support map values of type {type(value)}')

    def _should_ignore_field(self, fieldname):
        """
        Whether to ignore field for Lacework Query Language (LQL)
        """
        if not (isinstance(fieldname, str) and fieldname):
            return False

        for map in self.laceworkFieldMap:
            if not isinstance(map, dict):
                continue

            sigma_field = safe_get(map, 'sigmaField', str)
            if not sigma_field:
                continue

            # ignore
            if (
                map.get('matchType') == 'exact'
                and sigma_field == fieldname
                and map.get('action') == 'ignore'
            ):
                return True

        return False

    def _get_self_join_filter(self, fieldname):
        """
        Whether we're implementing a self-join filter within Lacework Query Language (LQL)
        """
        if not (isinstance(fieldname, str) and fieldname):
            return None

        for map in self.laceworkFieldMap:
            if not isinstance(map, dict):
                continue

            sigma_field = safe_get(map, 'sigmaField', str)
            if not sigma_field:
                continue

            sjf = map.get('selfJoinFilter')

            # self join filter
            if (
                map.get('action') == 'selfjoin'
                and sigma_field == fieldname
                and sjf and isinstance(sjf, str)
            ):
                return sjf

        return None

    @staticmethod
    def _check_unsupported_field(action, fieldname):
        if action == 'raise':
            raise BackendError(
                f'Lacework backend does not support the {fieldname} field')

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
            if (not lacework_field) and map.get('action') != 'raise':
                continue

            continyu = safe_get(map, 'continue', bool)

            # exact
            if (
                map.get('matchType') == 'exact'
                and sigma_field == fieldname
            ):
                self._check_unsupported_field(map.get('action'), fieldname)
                fieldname = lacework_field
                if not continyu:
                    return fieldname

            # startswith
            if (
                map.get('matchType') == 'startswith'
                and fieldname.startswith(sigma_field)
            ):
                self._check_unsupported_field(map.get('action'), fieldname)
                fieldname = f'{lacework_field}{fieldname[len(sigma_field):]}'
                if not continyu:
                    return fieldname

            # regex
            if map.get('matchType') == 'regex':
                fieldname_re = re.compile(sigma_field)
                fieldname_match = fieldname_re.match(fieldname)

                if not fieldname_match:
                    continue

                self._check_unsupported_field(map.get('action'), fieldname)

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

        # 1. Get Logsource
        self.logsource_type, self.logsource_name = self.get_logsource(rule)

        # 2. Get Logsource Config
        self.logsource_config = self.get_logsource_config(
            config, self.logsource_type, self.logsource_name)

        # 3. Get Query ID
        self.title, self.query_id = self.get_query_id(rule)

        # 4. Get Query Source
        self.query_sources = self.get_query_sources(
            self.logsource_name, self.logsource_config)

        # 5. Get Query Returns
        self.returns = self.get_query_returns(
            self.logsource_name, self.logsource_config)

        # 6. Get Query Text
        self.query_text = self.get_query_text(backend, conditions)

    def get_query_text(self, backend, rule_conditions):
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
        config_conditions = safe_get(self.logsource_config, 'conditions', list)
        filter_block = self.get_query_filter_block(backend, rule_conditions, config_conditions)

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
            source=',\n        '.join(self.query_sources)
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
        logsource_type, logsource_name = LaceworkQuery.get_logsource(sigmaparser.parsedyaml)
        logsource_config = LaceworkQuery.get_logsource_config(config, logsource_type, logsource_name)

        return safe_get(logsource_config, 'fieldMap', list)

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
    def get_logsource(rule):
        logsource = safe_get(rule, 'logsource', dict)
        if 'service' in logsource:
            return 'services', logsource['service']
        if {'product', 'category'}.issubset(set(logsource)):
            return 'product.categories', f"{logsource['product']}.{logsource['category']}"
        return 'unknown', 'unknown'

    @staticmethod
    def get_logsource_config(config, logsource_type, logsource_name):
        config = safe_get(config, logsource_type, dict)
        logsource_config = safe_get(config, logsource_name, dict)

        # 1. validate logsource service
        if not logsource_config:
            raise BackendError(
                f'Log source {logsource_name} is not supported by the Lacework backend')

        return logsource_config

    @staticmethod
    def get_query_id(rule):
        title = safe_get(rule, 'title', str) or 'Unknown'
        # TODO: might need to replace additional non-word characters
        query_id = f'Sigma_{title}'.replace(" ", "_").replace("/", "_Or_").replace("-", "_")

        return title, query_id

    @staticmethod
    def get_query_sources(logsource_name, logsource_config):
        # 4. validate service has a source mapping
        source = safe_get(logsource_config, 'source', str)
        sources = safe_get(logsource_config, 'sources', list)

        if sources:
            return sources
        elif source:
            return [source]

        raise BackendError(
            f'Lacework backend could not determine source for logsource {logsource_name}')

    @staticmethod
    def get_query_returns(logsource_name, logsource_config):
        returns = safe_get(logsource_config, 'returns', list)

        if not returns:
            raise BackendError(
                f'Lacework backend could not determine returns for logsource {logsource_name}')

        return returns

    @staticmethod
    def get_query_filter_block(backend, rule_conditions, config_conditions):
        filter_block_template = (
            'filter {{\n'
            '        {filter}\n'
            '    }}'
        )

        for parsed in rule_conditions:
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

            if config_conditions:
                filter += f" {' '.join(config_conditions)}"
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
        self.logsource_type, self.logsource_name = LaceworkQuery.get_logsource(rule)

        # 2. Get Service Config
        self.logsource_config = LaceworkQuery.get_logsource_config(
            config, self.logsource_type, self.logsource_name)

        # 3. Get Title
        # 4. Get Query ID
        self.title, self.query_id = LaceworkQuery.get_query_id(rule)

        # 5. Get Enabled
        self.enabled = False

        # 6. Get Policy Type
        self.policy_type = 'Violation'

        # 7. Get Alert Enabled
        self.alert_enabled = False

        # 8. Get Alert Profile
        self.alert_profile = self.get_alert_profile(
            self.logsource_name, self.logsource_config)

        # 9. Get Limit
        self.limit = 1000

        # 10. Get Severity
        self.severity = safe_get(rule, 'level', str) or 'medium'

        # 11. Get Description
        self.description = safe_get(rule, 'description', str)

        # 12. Get Remediation
        self.remediation = 'Remediation steps are not represented in Sigma rule specification'

    def __iter__(self):
        for key, attr in {
            'title': 'title',
            'enabled': 'enabled',
            'policyType': 'policy_type',
            'alertEnabled': 'alert_enabled',
            'alertProfile': 'alert_profile',
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
    def get_alert_profile(logsource_name, logsource_config):
        alert_profile = safe_get(logsource_config, 'alertProfile', str)

        if not alert_profile:
            raise BackendError(
                f'Lacework backend could not determine alert profile for logsource {logsource_name}')

        return alert_profile
