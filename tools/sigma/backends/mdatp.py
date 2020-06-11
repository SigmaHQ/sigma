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

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
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
        "ParentProcessName",
        "ParentCommandLine"
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
                "Command": ("ProcessCommandLine", self.default_value_mapping),
                "DeviceName": (self.id_mapping, self.default_value_mapping),
                "EventType": ("ActionType", self.default_value_mapping),
                "Image": ("FolderPath", self.default_value_mapping),
                "ImageLoaded": ("FolderPath", self.default_value_mapping),
                "LogonType": (self.id_mapping, self.logontype_mapping),
                "NewProcessName": ("FolderPath", self.default_value_mapping),
                "ParentImage": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "SourceImage": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "TargetImage": ("FolderPath", self.default_value_mapping),
                "User": (self.decompose_user, ),
            },
            "DeviceEvents": {
                "TargetFilename": ("FolderPath", self.default_value_mapping),
                "TargetImage": ("FolderPath", self.default_value_mapping),

                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceRegistryEvents": {
                "TargetObject": ("RegistryKey", self.default_value_mapping),
                "ObjectValueName": ("RegistryValueName", self.default_value_mapping),
                "Details": ("RegistryValueData", self.default_value_mapping),

                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceFileEvents": {
                "TargetFilename": ("FolderPath", self.default_value_mapping),
                "TargetFileName": ("FolderPath", self.default_value_mapping),

                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceNetworkEvents": {
                "Initiated": ("RemotePort", self.default_value_mapping),
                "Protocol": ("RemoteProtocol", self.default_value_mapping),
                "DestinationPort": ("RemotePort", self.default_value_mapping),
                "DestinationIp": ("RemoteIP", self.default_value_mapping),
                "DestinationIsIpv6": ("RemoteIP has \":\"", ),
                "SourcePort": ("LocalPort", self.default_value_mapping),
                "SourceIp": ("LocalIP", self.default_value_mapping),
                "DestinationHostname":  ("RemoteUrl", self.default_value_mapping),

                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            },
            "DeviceImageLoadEvents": {
                "ImageLoaded": ("FolderPath", self.default_value_mapping),

                "Image": ("InitiatingProcessFolderPath", self.default_value_mapping),
                "User":  (self.decompose_user, ),
            }
        }

    def id_mapping(self, src):
        """Identity mapping, source == target field name"""
        return src

    def default_value_mapping(self, val):
        op = "=="
        if type(val) == str:
            if "*" in val[1:-1]:     # value contains * inside string - use regex match
                op = "matches regex"
                val = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', val)
                val = re.sub('\\*', '.*', val)
                val = re.sub('\\?', '.', val)
            else:                           # value possibly only starts and/or ends with *, use prefix/postfix match
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
        self.table = None
        self.category = sigmaparser.parsedyaml['logsource'].get('category')
        self.product = sigmaparser.parsedyaml['logsource'].get('product')
        self.service = sigmaparser.parsedyaml['logsource'].get('service')

        if (self.category, self.product, self.service) == ("process_creation", "windows", None):
            self.table = "DeviceProcessEvents"
        elif (self.category, self.product, self.service) == (None, "windows", "powershell"):
            self.table = "DeviceEvents"
            self.orToken = ", "

        return super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if self.table is None:
            raise NotSupportedError("No MDATP table could be determined from Sigma rule")
        if self.table == "DeviceEvents" and self.service == "powershell":
            return "%s | where tostring(extractjson('$.Command', AdditionalFields)) in~ " % self.table
        return "%s | where " % self.table

    @wrapper
    def generateMapItemNode(self, node):
        """
        ATP queries refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        # handle map items with values list like multiple OR-chained conditions
        if type(value) == list:
            return self.generateORNode([(key, v) for v in value])
        elif key == "EventID":            # EventIDs are not reflected in condition but in table selection
            if self.product == "windows":
                if self.service == "sysmon" and value == 1 \
                        or self.service == "security" and value == 4688:    # Process Execution
                    self.table = "DeviceProcessEvents"
                    return None
                elif self.service == "sysmon" and value == 3:               # Network Connection
                    self.table = "DeviceNetworkEvents"
                    return None
                elif self.service == "sysmon" and value == 7:               # Image Load
                    self.table = "DeviceImageLoadEvents"
                    return None
                elif self.service == "sysmon" and value == 8:               # Create Remote Thread
                    self.table = "DeviceEvents"
                    return "ActionType == \"CreateRemoteThreadApiCall\""
                elif self.service == "sysmon" and value == 11:              # File Creation
                    self.table = "DeviceFileEvents"
                    return "ActionType == \"FileCreated\""
                elif self.service == "sysmon" and value == 23:              # File Deletion
                    self.table = "DeviceFileEvents"
                    return "ActionType == \"FileDeleted\""
                elif self.service == "sysmon" and value == 12:              # Create/Delete Registry Value
                    self.table = "DeviceRegistryEvents"
                    return None
                elif self.service == "sysmon" and value == 13 \
                        or self.service == "security" and value == 4657:    # Set Registry Value
                    self.table = "DeviceRegistryEvents"
                    return "ActionType == \"RegistryValueSet\""
                elif self.service == "security" and value == 4624:
                    self.table = "DeviceLogonEvents"
                    return None
                else:
                    if not self.table:
                        raise NotSupportedError("No sysmon Event ID provided")
                    else:
                        raise NotSupportedError("No mapping for Event ID %s" % value)
        elif type(value) in (str, int):     # default value processing
            try:
                mapping = self.fieldMappings[self.table][key]
            except KeyError:
                raise NotSupportedError("No mapping defined for field '%s' in '%s'" % (key, self.table))
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    conds = mapping(key, value)
                    return self.andToken.join(["{} {}".format(*cond) for cond in conds])
            elif len(mapping) == 2:
                result = list()
                # iterate mapping and mapping source value synchronously over key and value
                for mapitem, val in zip(mapping, node):
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(val))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

        return super().generateMapItemNode(node)
