# Splunk Datamodel backend for sigmac by mf1d3l (twitter: @mfidel19), 
# greatly inspired from the original Splunk Backend by Thomas Patzke, Florian Roth and Roey

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

import yaml
import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin
from .cim import default_datamodels

class SplunkDMBackend(SingleTextQueryBackend):
    """ (Experimental) Converts Sigma rule into a Splunk syntax leveraging Datamodel acceleration when possible (rolls back to standard SPL query if necessary)"""
    identifier = "splunkdm"
    active = True
    index_field = "index"

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "\"%s\""
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def resolveDatamodel(self, sigmaparser):
        try:
            rule_logsrc = sigmaparser.parsedyaml['logsource']
            datamodels = self.datamodels
            for dm in datamodels:
                for ds in datamodels[dm]['datasets']:
                    mapping = datamodels[dm]['datasets'][ds]['mapping']
                    for entry in mapping:
                        if entry in rule_logsrc and mapping[entry] == rule_logsrc[entry]:
                            return dm, ds
        except:
            raise Exception("[!] Failure to convert sigma rule: No Datamodel found that is corresponding to target sigma rule")

    def addDatamodel(self, sigmaparser):
        try:
            self.datamodel = self.backend_options['datamodel']
            self.dataset = self.backend_options['dataset']
        except:
            try:
               self.datamodel, self.dataset = self.resolveDatamodel(sigmaparser)
            except:
                try:
                    datamodel_resolution = self.backend_options['datamodel_resolution']
                except:
                    datamodel_resolution = "default"
                if datamodel_resolution == "debug":
                    raise Exception("[!] Failure to convert sigma rule: Backend is unable to automatically find a Datamodel for the target sigma rule, you may try to explicit one with the backend options")
                else:
                    pass

    def loadDatamodel(self):
        try:
            path = self.backend_options['datamodels_path']
            with open(path, 'r') as stream:
                self.datamodels = yaml.safe_load(stream)
        except:
           self.datamodels = default_datamodels

    def normalizeField(self, field):
        normalized = False
        datamodel = self.datamodel
        dataset = self.dataset
        datamodels = self.datamodels
        try:
            for f in datamodels[datamodel]['datasets'][dataset]['fields']:
                if field in datamodels[datamodel]['datasets'][dataset]['fields'][f]:
                    field = f
                    normalized = True
                    return field
                elif field == f:
                    normalized = True
                    return field
        except:
            pass

        if normalized or self.backend_options['normalization_mode'] == "override":
            return field
        else:
           raise Exception("[!] Failure to convert sigma rule: No normalization available for field "+ field + " in "+ datamodel + "." + dataset)

    def applyNormalization(self, sigmaparser):
        datamodel = self.datamodel
        dataset = self.dataset
        if 'fields' in sigmaparser.parsedyaml:
            newfields = []
            for field in sigmaparser.parsedyaml['fields']:
                field = self.normalizeField(field)
                newfields.append(dataset + '.' + field)
            sigmaparser.parsedyaml.update({'fields': newfields})

        newdetection = {}
        for subkey in sigmaparser.parsedyaml['detection']:
            newdetection.update({subkey: {}})
            if subkey != 'condition':
                for field in sigmaparser.parsedyaml['detection'][subkey]:
                    nativefield = field.split("|", 1)[0]
                    newfield = self.normalizeField(nativefield)
                    newfield = dataset + '.' + newfield
                    try:
                        commands = field.split("|", 1)[1]
                        newfield = newfield + '|' + commands
                    except:
                        pass
                    values = sigmaparser.parsedyaml['detection'][subkey][field]
                    newdetection[subkey].update({newfield: values})
            else:
                    newdetection[subkey] = sigmaparser.parsedyaml['detection'][subkey]
        sigmaparser.parsedyaml.update({'detection': newdetection})
        sigmaparser.parse_sigma()
        return sigmaparser

    def generateMapItemListNode(self, key, value):
        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateAggregationAlt(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val | search val %s %s" % (agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val by %s| search val %s %s" % (agg.groupfield, agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)

    def generateAggregation(self, agg):
        if self.generate_mode == "Datamodel":
            raise Exception("Aggregation not yet supported for datamodel")
        elif self.generate_mode == "Alternative":
            return self.generateAggregationAlt(agg)

    def generateBefore(self, sigmaparser):
        try:
            datamodel = self.datamodel
            dataset = self.dataset
            before = "| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=" + datamodel + "." + dataset + " where "
        except:
            before = ""

        return before

    def generateBeforeAlt(self, sigmaparser):
        before = ""
        return before

    def generateAlt(self, sigmaparser):
        self.generate_mode = "Alternative"
        columns = list()
        mapped =None
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                if type(mapped) == str:
                    columns.append(mapped)
                elif type(mapped) == list:
                    columns.extend(mapped)
                else:
                    raise TypeError("Field mapping must return string or list")

            fields = ",".join(str(x) for x in columns)
            fields = " | table " + fields

        except KeyError:    # no 'fields' attribute
            mapped = None
            pass

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBeforeAlt(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after
            if mapped is not None:
                result += fields

            return result

    def generateDM(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        self.generate_mode = "Datamodel"
        columns = list()
        mapped =None
        sigmaparser = self.applyNormalization(sigmaparser)
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                if type(mapped) == str:
                    columns.append(mapped)
                elif type(mapped) == list:
                    columns.extend(mapped)
                else:
                    raise TypeError("Field mapping must return string or list")

            fields = " ".join(str(x) for x in columns)
            fields = " by " + fields

        except KeyError:    # no 'fields' attribute
            mapped = None
            pass

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)
            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after
            if mapped is not None:
                result += fields

            return result

    def generate(self, sigmaparser):
        try:
            normalization_mode = self.backend_options['normalization_mode']
        except:
            normalization_mode = "default"

        self.loadDatamodel()
        self.addDatamodel(sigmaparser)
        alt_query = self.generateAlt(sigmaparser)

        try:
            return self.generateDM(sigmaparser)
        except Exception as exc:
             if normalization_mode == "debug":
                 print(exc)
             else:
                 return alt_query
