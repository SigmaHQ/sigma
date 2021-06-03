# Output backends for sigmac
# Copyright 2018 Thomas Patzke

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
from functools import wraps
from .base import SingleTextQueryBackend
from .exceptions import NotSupportedError
from ..parser.modifiers.base import SigmaTypeModifier


def wrapper(method):
    @wraps(method)
    def _impl(self, method_args):
        key, value, *_ = method_args
        if '.keyword' in key:
            key = key.split('.keyword')[0]
        if key not in self.skip_fields:
            method_output = method(self, method_args)
            return method_output
        else:
            return
    return _impl

class WindowsDefenderATPBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Microsoft Defender ATP Hunting Queries."""
    identifier = "mdatp"
    active = True
    config_required = False

    reEscape = re.compile('(?:\\\\)?(")')
    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isnull(%s)"
    notNullExpression = "isnotnull(%s)"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"

    skip_fields = {
        "Description",
        "_exists_",
        "FileVersion",
        "Product",
        "Company",
        "IMPHASH",
    }

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.fieldMappings = {       # mapping between Sigma and ATP field names
            # Supported values:
            # (field name mapping, value mapping): distinct mappings for field name and value, may be a string (direct mapping) or function maps name/value to ATP target value
            # (mapping function,): receives field name and value as parameter, return list of 2 element tuples (destination field name and value)
            # (replacement, ): Replaces field occurrence with static string
            "DeviceProcessEvents": {
                "AccountName": (self.id_mapping, self.default_value_mapping),
                "CommandLine": ("ProcessCommandLine", self.default_value_mapping),
                "DeviceName": (self.id_mapping, self.default_value_mapping),
                "EventType": ("ActionType", self.default_value_mapping),
                "FileName": (self.id_mapping, self.default_value_mapping),
                "Image": ("FolderPath", self.default_value_mapping),
                "ImagePath": ("FolderPath", self.default_value_mapping),
                "ImageLoaded": ("FolderPath", self.default_value_mapping),
                "LogonType": (self.id_mapping, self.logontype_mapping),
                "NewProcessName": ("FolderPath", self.default_value_mapping),
                "ParentCommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ParentName": ("InitiatingProcessFileName", self.default_value_mapping),
                "ParentProcessName": ("InitiatingProcessFileName", self.default_value_mapping),
                "ParentImage": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "SourceImage": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "TargetImage": ("FolderPath", self.default_value_mapping),
                "User": (self.decompose_user, ),
            },
            "DeviceEvents": {
                "AccountName": (self.id_mapping, self.default_value_mapping),
                "CommandLine": ("ProcessCommandLine", self.default_value_mapping),
                "DestinationHostname":  ("RemoteUrl", self.default_value_mapping),
                "DestinationIp": ("RemoteIP", self.default_value_mapping),
                "DestinationPort": ("RemotePort", self.porttype_mapping),
                "EventType": ("ActionType", self.default_value_mapping),
                "FileName": (self.id_mapping, self.default_value_mapping),
                "ParentCommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ParentProcessName": ("InitiatingProcessParentFileName", self.default_value_mapping),
                "ProcessName": ("InitiatingProcessFileName", self.default_value_mapping),
                "ServiceFileName": ("FileName", self.default_value_mapping),
                "SourceIp": ("LocalIP", self.default_value_mapping),
                "SourcePort": ("LocalPort", self.porttype_mapping),
                "TargetFilename": ("FolderPath", self.default_value_mapping),
                "TargetObject": ("RegistryKey", self.default_value_mapping),
                "TargetImage": ("FolderPath", self.default_value_mapping),
                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceRegistryEvents": {
                "DataType": ("RegistryValueType", self.default_value_mapping),
                "Details": ("RegistryValueData", self.default_value_mapping),
                "EventType": ("ActionType", self.default_value_mapping),
                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "CommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ObjectValueName": ("RegistryValueName", self.default_value_mapping),
                "ParentCommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ProcessName": ("InitiatingProcessFileName", self.default_value_mapping),
                "ParentName": ("InitiatingProcessParentFileName", self.default_value_mapping),
                "ParentProcessName": ("InitiatingProcessParentFileName", self.default_value_mapping),
                "TargetObject": ("RegistryKey", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceFileEvents": {
                "FileName": (self.id_mapping, self.default_value_mapping),
                "OriginIp": ("FileOriginIp", self.default_value_mapping),
                "OriginReferrer": ("FileOriginReferrerUrl", self.default_value_mapping),
                "OriginUrl": ("FileOriginUrl", self.default_value_mapping),
                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "CommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ParentCommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ProcessName": ("InitiatingProcessFileName", self.default_value_mapping),
                "ParentName": ("InitiatingProcessParentFileName", self.default_value_mapping),
                "ParentProcessName": ("InitiatingProcessParentFileName", self.default_value_mapping),
                "TargetFilename": ("FolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceNetworkEvents": {
                "DestinationHostname": ("RemoteUrl", self.default_value_mapping),
                "DestinationIp": ("RemoteIP", self.default_value_mapping),
                "DestinationIsIpv6": ("RemoteIP has \":\"", ),
                "DestinationPort": ("RemotePort", self.porttype_mapping),
                "DeviceName": (self.id_mapping, self.default_value_mapping),
                "EventType": ("ActionType", self.default_value_mapping),
                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "CommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "Initiated": ("RemotePort", self.default_value_mapping),
                "ParentCommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ProcessName": ("InitiatingProcessFileName", self.default_value_mapping),
                "Protocol": ("RemoteProtocol", self.default_value_mapping),
                "SourceIp": ("LocalIP", self.default_value_mapping),
                "SourcePort": ("LocalPort", self.porttype_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceImageLoadEvents": {
                "DeviceName": (self.id_mapping, self.default_value_mapping),
                "EventType": ("ActionType", self.default_value_mapping),
                "FileName": (self.id_mapping, self.default_value_mapping),
                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "ImageLoaded": ("FolderPath", self.default_value_mapping),
                "ParentCommandLine": ("InitiatingProcessCommandLine", self.default_value_mapping),
                "ParentProcessName": ("InitiatingProcessParentFileName", self.default_value_mapping),
                "ProcessName": ("InitiatingProcessFileName", self.default_value_mapping),
                "TargetImage": ("FolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            }
        }
        self.current_table = ""

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = []
        for g in generated:
            if g and g.startswith("ActionType"):
                if not any([i for i in filtered if i.startswith("ActionType")]):
                    filtered.append(g)
                else:
                    continue
            elif g is not None:
                filtered.append(g)
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None

    def id_mapping(self, src):
        """Identity mapping, source == target field name"""
        return src

    def default_value_mapping(self, val):
        op = "=~"
        if type(val) == str:
            if "*" in val[1:-1]:
                # value contains * inside string - use regex match
                op = "matches regex"
                val = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', val)
                val = re.sub('\\*', '.*', val)
                val = re.sub('\\?', '.', val)
            else:
                # value possibly only starts and/or ends with *, use prefix/postfix match
                if val.endswith("*") and val.startswith("*"):
                    op = "contains"
                    val = self.cleanValue(val[1:-1])
                elif val.endswith("*"):
                    op = "startswith"
                    val = self.cleanValue(val[:-1])
                elif val.startswith("*"):
                    op = "endswith"
                    val = self.cleanValue(val[1:])

        return "%s \"%s\"" % (op, val)

    def porttype_mapping(self, val):
        return "%s \"%s\"" % ("==", val)

    def logontype_mapping(self, src):
        """Value mapping for logon events to reduced ATP LogonType set"""
        logontype_mapping = {
            2: "Interactive",
            3: "Network",
            4: "Batch",
            5: "Service",
            7: "Interactive",   # unsure
            8: "Network",
            9: "Interactive",   # unsure
            10: "Remote interactive (RDP) logons",  # really the value?
            11: "Interactive"
        }
        try:
            return logontype_mapping[int(src)]
        except KeyError:
            raise NotSupportedError("Logon type %d unknown and can't be mapped" % src)

    def decompose_user(self, src_field, src_value):
        """Decompose domain\\user User field of Sysmon events into ATP InitiatingProcessAccountDomain and InititatingProcessAccountName."""
        reUser = re.compile("^(.*?)\\\\(.*)$")
        m = reUser.match(src_value)
        if m:
            domain, user = m.groups()
            return (("InitiatingProcessAccountDomain",  self.default_value_mapping(domain)), ("InititatingProcessAccountName",  self.default_value_mapping(user)))
        else:   # assume only user name is given if backslash is missing
            return (("InititatingProcessAccountName", self.default_value_mapping(src_value)))

    def generate(self, sigmaparser):
        self.tables = []
        try:
            self.category = sigmaparser.parsedyaml['logsource'].setdefault('category', None)
            self.product = sigmaparser.parsedyaml['logsource'].setdefault('product', None)
            self.service = sigmaparser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            self.category = None
            self.product = None
            self.service = None

        if (self.category, self.product, self.service) == ("process_creation", "windows", None):
            self.tables.append("DeviceProcessEvents")
            self.current_table = "DeviceProcessEvents"
        elif (self.category, self.product, self.service) == ("registry_event", "windows", None):
            self.tables.append("DeviceRegistryEvents")
            self.current_table = "DeviceRegistryEvents"
        elif (self.category, self.product, self.service) == ("file_event", "windows", None):
            self.tables.append("DeviceFileEvents")
            self.current_table = "DeviceFileEvents"
        elif (self.category, self.product, self.service) == ("image_load", "windows", None):
            self.tables.append("DeviceImageLoadEvents")
            self.current_table = "DeviceImageLoadEvents"
        elif (self.category, self.product, self.service) == ("network_connection", "windows", None):
            self.tables.append("DeviceNetworkEvents")
            self.current_table = "DeviceNetworkEvents"
        elif (self.category, self.product, self.service) == (None, "windows", "powershell"):
            self.tables.append("DeviceEvents")
            self.current_table = "DeviceEvents"
            self.orToken = ", "
        elif (self.category, self.product, self.service) == (None, "windows", "security"):
            self.tables.append("DeviceAlertEvents")
            self.current_table = "DeviceAlertEvents"

        return super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if not any(self.tables):
            raise NotSupportedError("No MDATP table could be determined from Sigma rule")
        # if self.tables in "DeviceEvents" and self.service == "powershell":
        #     return "%s | where tostring(extractjson('$.Command', AdditionalFields)) in~ " % self.tables
        if len(self.tables) == 1:
            if self.tables[0] == "DeviceEvents" and self.service == "powershell":
                return "%s | where tostring(extractjson('$.Command', AdditionalFields)) in~ " % self.tables
            return "%s | where " % self.tables[0]
        else:
            if "DeviceEvents" in self.tables and self.service == "powershell":
                return "union %s | where tostring(extractjson('$.Command', AdditionalFields)) in~ " % ", ".join(self.tables)
            return "union %s | where " % ", ".join(self.tables)

    def generateORNode(self, node):
        generated = super().generateORNode(node)
        if generated:
            return "%s" % generated
        return generated

    def cleanValue(self, val):
        if self.reEscape:
            val = self.reEscape.sub(self.escapeSubst, val)
        return val

    def mapEventId(self, event_id):
        if self.product == "windows":
            if self.service == "sysmon" and event_id == 1 \
                    or self.service == "security" and event_id == 4688:  # Process Execution
                self.tables.append("DeviceProcessEvents")
                self.current_table = "DeviceProcessEvents"
                return None
            elif self.service == "sysmon" and event_id == 3:  # Network Connection
                self.tables.append("DeviceNetworkEvents")
                self.current_table = "DeviceNetworkEvents"
                return None
            elif self.service == "sysmon" and event_id == 7:  # Image Load
                self.tables.append("DeviceImageLoadEvents")
                self.current_table = "DeviceImageLoadEvents"
                return None
            elif self.service == "sysmon" and event_id == 8:  # Create Remote Thread
                self.tables.append("DeviceEvents")
                self.current_table = "DeviceEvents"
                return "ActionType == \"CreateRemoteThreadApiCall\""
            elif self.service == "sysmon" and event_id == 11:  # File Creation
                self.tables.append("DeviceFileEvents")
                self.current_table = "DeviceFileEvents"
                return "ActionType == \"FileCreated\""
            elif self.service == "sysmon" and event_id == 23:  # File Deletion
                self.tables.append("DeviceFileEvents")
                self.current_table = "DeviceFileEvents"
                return "ActionType == \"FileDeleted\""
            elif self.service == "sysmon" and event_id == 12:  # Create/Delete Registry Value
                self.tables.append("DeviceRegistryEvents")
                self.current_table = "DeviceRegistryEvents"
                return None
            elif self.service == "sysmon" and event_id == 13 \
                    or self.service == "security" and event_id == 4657:  # Set Registry Value
                self.tables.append("DeviceRegistryEvents")
                self.current_table = "DeviceRegistryEvents"
                return "ActionType == \"RegistryValueSet\""
            elif self.service == "security" and event_id == 4624:
                self.tables.append("DeviceLogonEvents")
                self.current_table = "DeviceLogonEvents"
                return None
            elif self.service == "system" and event_id == 7045: # New Service Install
                self.tables.append("DeviceEvents")
                self.current_table = "DeviceEvents"
                return "ActionType == \"ServiceInstalled\""
            else:
                if not self.tables:
                    raise NotSupportedError("No sysmon Event ID provided")
                else:
                    raise NotSupportedError("No mapping for Event ID %s" % event_id)

    @wrapper
    def generateMapItemNode(self, node):
        """
        ATP queries refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        if key == "EventID":
            # EventIDs are not reflected in condition but in table selection
            if isinstance(value, str) or isinstance(value, int):
                value = int(value) if isinstance(value, str) else value
                return self.mapEventId(value)
            elif isinstance(value, list):
                return_payload = []
                for event_id in value:
                    res = self.mapEventId(event_id)
                    if res:
                        return_payload.append(res)
                if len(return_payload) == 1:
                    return return_payload[0]
                elif not any(return_payload):
                    return None
                else:
                    return "(%s)" % self.generateORNode(
                    [(key, v) for v in value]
                    )
        if type(value) == list:         # handle map items with values list like multiple OR-chained conditions
            return "(%s)" % self.generateORNode(
                    [(key, self.cleanValue(v)) for v in value]
                    )
        elif type(value) in (str, int):     # default value processing
            try:
                mapping = self.fieldMappings[self.current_table][key]
            except KeyError:
                raise NotSupportedError("No mapping defined for field '%s' in '%s'" % (key, self.tables))
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    conds = mapping(key, self.cleanValue(value))
                    return self.andToken.join(["{} {}".format(*cond) for cond in conds])
            elif len(mapping) == 2:
                result = list()
                for mapitem, val in zip(mapping, node):     # iterate mapping and mapping source value synchronously over key and value
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(self.cleanValue(val)))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        elif isinstance(value, SigmaTypeModifier):
            try:
                mapping = self.fieldMappings[self.current_table][key]
            except KeyError:
                raise NotSupportedError("No mapping defined for field '%s' in '%s'" % (key, self.tables))
            return self.generateMapItemTypedNode(mapping[0], value)

        return super().generateMapItemNode(node)
