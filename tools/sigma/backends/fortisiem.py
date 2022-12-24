# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth

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

import sys
import csv 
import sigma
import yaml
import re
import copy

from sigma.backends.exceptions import NotSupportedError
from .mixins import RulenameCommentMixin, QuoteCharMixin
from sigma.parser.modifiers.base import SigmaTypeModifier
from .base import BaseBackend

class FortisemBackend(RulenameCommentMixin, BaseBackend, QuoteCharMixin):
    """Base class for Fortisem backends that generate one text-based expression from a Sigma rule"""
    identifier = "fortisiem"
    active = True

    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "%s"
    strValueExpression = "\"%s\""
    nullExpression = "%s IS NULL"
    notNullExpression = "%s IS NOT NULL"
    mapExpression = "%s=%s"
    mapExpressionNot = "%s!=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN (%s)"
    regExpression = "%s REGEXP ( %s )"
    mapListValueExpressionNot = "%s NOT IN (%s)"
    regExpressionNot = "%s NOT REGEXP ( %s )"

    sort_condition_lists = False        # Sort condition items for AND and OR conditions

    ymlAttr2FortiSIEMAttr = {}
    fortiSIEMAttrType = {}
    fileFilterDicts= {}
    WindowsSysmonCode2FortiSIEMEvtTy = {}

    product = None
    service = None
    category = None
    curAttrs= set()
    sourceValueForWinAppEvtTy= None

    #if Attribute value is too long, this rule will be skip.
    isValTooLong = False
    MAX_LEN = 2271

    techniqueMap = {}
    ruleType = None
    ruleIndex = 1;

    def __init__(self, sigmaconfig, backend_options=dict()):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified about the used backend class by
        passing the object instance to it.
        """
        super().__init__(sigmaconfig, backend_options)
        self.setRuleType(backend_options)
        self.loadCSVfiles()
        self.loadMitreAttackMatrixFile(backend_options);

    def initialize(self):
        return "<Rules>"

    def finalize(self):
        return "</Rules>"
     
    # It's used to check whether the format of yml file is right. 
    def ymlValidator(self, node,regdicts={}):
        if type(node) == sigma.parser.condition.ConditionAND:
            for val in node:
                if self.ymlValidator(val) == False:
                    return False
            return True
        elif type(node) == sigma.parser.condition.ConditionOR:
            for val in node:
                if self.ymlValidator(val) == False:
                    return False
            return True
        elif type(node) == sigma.parser.condition.ConditionNOT:
            if self.ymlValidator(node.items) ==  False:
                return False
            return True
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return True
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return True
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            if self.ymlValidator(node.items) == False:
                return False
            return True
        elif type(node) == tuple:
            fieldname, value = node
            if fieldname is None:
                return False
            return True
        elif type(node) in (str, int):
            return False
        elif type(node) == list:
            for value in node:
                if self.ymlValidator(value) == False:
                    return False
            return True
        else:
            return False
        

    def notSupportedLogsource(self, product, service):
        if product is None:
            product = ""

        if service is None:
            service = ""

        for key, val in self.fileFilterDicts.items():
            if key == product:
                if val == "":
                    return True
                else:
                    val = ",%s," % val
                    service = ",%s," % service
                    if val.find(service) != -1:
                        return True
        return False

    def loadCSVfiles(self):
        #It's used to map field name to internal attributes in FSIM
        if len(self.ymlAttr2FortiSIEMAttr) == 0:
            with open("./tools/config/fortisiem/FortiSIEM_EventAttributeMapping.csv", newline='') as csvfile:
                spamreader = csv.reader(csvfile, delimiter=',')
                for row in spamreader:
                    if len(row) < 2:
                        continue;
                    elif len(row) == 2:
                        self.fortiSIEMAttrType[row[1]] = "string"
                    else:
                        self.fortiSIEMAttrType[row[1]] = row[2]

                    self.ymlAttr2FortiSIEMAttr[row[0]] = row[1]
        #It's used to map event id to event type.
        if len(self.WindowsSysmonCode2FortiSIEMEvtTy) == 0:
            with open("./tools/config/fortisiem/FortiSIEM_SysMonEventTypeMapping.csv", newline='') as csvfile:
                spamreader = csv.reader(csvfile, delimiter=',')
                for row in spamreader:
                    if len(row) > 1:
                        self.WindowsSysmonCode2FortiSIEMEvtTy[row[0]] = row[1]

        #It's used to skip some files. When yml file match the constraints in it, we don't need generate rule from that yml file.
        if len(self.fileFilterDicts) == 0:
             with open("./tools/config/fortisiem/FortiSIEM_SkipUnsupportedLogSources.csv", newline='') as csvfile:
                 spamreader = csv.reader(csvfile, delimiter=',')
                 for row in spamreader:
                     if len(row) > 1:
                         self.fileFilterDicts[row[0]] = row[1]


    def loadMitreAttackMatrixFile(self, backend_options):
        techniquefile = backend_options.get("attackMapFile", None)
        if techniquefile is None:
            return

        if len(self.techniqueMap) == 0:
            with open(techniquefile, newline='') as f:
                spamreader = csv.reader(f, delimiter=',')
                for row in spamreader:
                    if len(row) < 3:
                        continue
                    else:
                        if row[2] != "":
                            self.techniqueMap[row[0]] = row[2]

    def formatSubFunctionAndTechniqueId(self, techniqueIds):
        sub_function_str = "Persistence"; 
        technique_str = None
        techniqueIds = sorted(techniqueIds)
        if len(techniqueIds) == 0:
           return sub_function_str, technique_str

        technique_str = ','.join(techniqueIds)
        for item in techniqueIds:
            tmp = self.techniqueMap.get(item, None)
            if tmp is None:
                continue
            tmp = tmp.split(",")
            sub_function_str = tmp[0];
            break;
        
        return sub_function_str, technique_str

    def formatRuleName(self, name):
        #ruleName has invalid characters. It only accepts: a-zA-Z0-9 \/:.$-
        ruleName = re.sub('\s*[^a-zA-Z0-9 \/:.$_\'\"-]+\s*', ' ', name)
        ruleName = re.sub('_', '-', ruleName)
        ruleName = re.sub('[\'"\(\)+,]*', '', ruleName)
        return ruleName

    def formatRuleTitle(self, name):
        #IncidentTitle has invalid characters. It only accepts: a-zA-Z0-9 _$-
        titleName = re.sub('\s*[^a-zA-Z0-9 _-]+\s*', ' ', name)
        return titleName;

    def setRuleType(self, backend_options):
        ruletype = backend_options.get("ruleType", None)
        ruleStartIndex = backend_options.get("ruleIndex", None)
        if ruletype is not None:
            self.ruleType = ruletype
        if ruleStartIndex is not None:
            self.ruleIndex = int(ruleStartIndex)

    def convertFieldNameToInterAttrName(self, fieldname):
        val = self.ymlAttr2FortiSIEMAttr.get(fieldname, None)
        if val is None:
            interfieldname = fieldname
        else:
            interfieldname = val

        self.curAttrs.add(interfieldname)
        return interfieldname

    def convertFieldValToInterVal(self, fieldname, value):
        val = self.generateValueNode(value);

        interfieldname = self.convertFieldNameToInterAttrName(fieldname)

        attrType = self.fortiSIEMAttrType.get(interfieldname, None)
        if val.find('.*') != -1:
             attrType = "string";

        if interfieldname == "eventType" and val.isdigit():
            val = self.formatEvtTypeVal(val)
        elif attrType is None or attrType == "string":
            val = self.strValueExpression % val;

        return val

    def formatEvtTypeVal(self, code):
        val = "\".*%s.*\"" % code
        if self.product == "windows":
            val = "\"Win-.*%s.*\"" % code

        if self.product == "windows" and ( self.service == "sysmon" or (self.service is None and  self.category == "sysmon")) :
            val = self.WindowsSysmonCode2FortiSIEMEvtTy.get(code, None)
            if val is None:
                val = "\"Win-Sysmon-%s-.*\"" % code
            else:
                evt = val.split(",")
                val = ",".join(["\"%s\"" % item for item in evt])
        elif self.product == "windows" and (self.service == "system" or (self.service is None and  self.category == "system")):
            val = "\"Win-System-%s\"" % code
        elif self.product == "windows" and ( ( self.service == "powershell" or self.service == "powershell-classic") or (self.service is None and ( self.category == "powershell" or self.category == "powershell-classic"))):
            val = "\"Win-PowerShell-%s\"" % code
        elif self.product == "windows" and ( self.service == "security" or (self.service is None and  self.category == "security")):
            val = "\"Win-Security-%s\"" % code
        elif self.product == "windows" and ( self.service == "application" or (self.service is None and  self.category == "application")):
            if self.sourceValueForWinAppEvtTy is not None:
                val = "\"Win-App-%s-%s\"" % ( self.sourceValueForWinAppEvtTy, code)
        return val

    def convertStrToRegstr(self, value):
        val = value.replace('\\"', '"')
        val = val.replace('\\', "\\\\")
        val = val.replace('"', '\\"')
        val = val.replace('.', "\\\\.")
        val = val.replace('(', "\\\\(")
        val = val.replace(')', "\\\\)")
        val = val.replace('&', "&amp;")
        val = val.replace('<', "&lt;")
        val = val.replace('>', "&gt;")
        val = val.replace('[', "\\\\[")
        val = val.replace(']', "\\\\]")
        val = val.replace('|', "\\\\|")
        val = val.replace('}', "\\\\}")
        val = val.replace('{', "\\\\{")
        val = val.replace('^', "\\\\^")
        val = val.replace('$', "\\\\$")
        val = val.replace('+', "\\\\+")
        val = val.replace('!', "\\\\!")
        val = val.replace('?', "\\\\?")
        val = val.replace('*', ".*")
        return val 

    def convertStrToXmlstr(self, value):
        val = value.replace('&', "&amp;")
        return val

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        if type(parsed.parsedSearch) == sigma.parser.condition.NodeSubexpression:
           result =  result[1:-1]   
        return result

    def generateMapItemNode(self, node, regdicts, isnot=False):
        fieldname, value = node
        interName = self.convertFieldNameToInterAttrName(fieldname)

        mapExp = self.mapExpression
        regExp = self.regExpression
        nullExp = self.nullExpression
        listExp = self.mapListValueExpression
        if isnot:
            mapExp = self.mapExpressionNot
            regExp = self.regExpressionNot
            nullExp = self.notNullExpression
            listExp = self.mapListValueExpressionNot

        if not value:
            return nullExp % (interName, )
        elif self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            val = self.convertFieldValToInterVal(interName, value)
            if len(val) > self.MAX_LEN:
                self.isValTooLong = True

            if interName== "eventType":
                if val.find(".*") == -1 and val.find(",") == -1:
                    return mapExp % (interName, val)
                elif val.find(".*") == -1 and val.find(",") != -1:
                    return listExp % (interName, val) 
                else:
                    return regExp % (interName, val)
            else:
                if val.find(".*") == -1:
                    return mapExp % (interName, val)
                else:
                    return regExp % (interName, val)

        elif type(value) == list:
            #print(self.generateMapItemListNode(interName, value, isnot))
            return self.generateMapItemListNode(interName, value, isnot)
        elif isinstance(value, SigmaTypeModifier):
            val = regdicts.get(interName, None)
            if val is None: 
                regList = set()
                regList.add(value.__str__())
                regdicts[interName] = regList
            else:
                val.add(value.__str__())
                regdicts[interName] = val
            return None;
            #return self.generateMapItemTypedNode(interName, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateRegExpresion(self, regD, isnot=False):
        if len(regD) == 0:
            return None

        result = ""
        for key in regD.keys():
            vals = regD[key]
            res = ""
            if type(vals) == set:
                vals = sorted(vals)
                for val in vals:
                    res = res + ("|%s" % val)
                res = res[1:]
                res = "\"%s\"" % res
               
            if result != "" and isnot:
                result += " AND "
            elif result != "" and isnot==False:
                result += " OR "

            if len(res) > self.MAX_LEN:
                self.isValTooLong = True

            if isnot:
                result += self.regExpressionNot % (key, res)
            else:
                result += self.regExpression % (key, res)
            result = result.replace('\\', "\\\\")
        #print(result)
        return result

    def generateMapItemListNode(self, key, value, isnot=False):
        key = self.convertFieldNameToInterAttrName(key)

        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        tmp = []
        tmpReg = []
        for item in value:
            val = self.convertFieldValToInterVal(key, item)
            valset = set()
            if key == "eventType": 
                valset = val.split(",")
            else:
                valset.add(val)

            for item in valset:
                if item.find(".*") == -1:
                    tmp.append(item)
                else:
                    tmpReg.append(val)        

        tmpstr=''
        mapExp = self.mapExpression
        mapListExp = self.mapListValueExpression
        regExp = self.regExpression
        if isnot:
            mapExp = self.mapExpressionNot
            mapListExp = self.mapListValueExpressionNot
            regExp = self.regExpressionNot

        if len(tmp) == 1:
            tmpstr = (mapExp %  (key, tmp[0]))
        elif len(tmp) > 1:
            tmp = sorted(tmp)
            tmpstr = (",".join(['%s' % (item) for item in tmp]))
            tmpstr = mapListExp % (key, tmpstr)
        
        tmpregstr=''
        if len(tmpReg) > 0:
            tmpReg = sorted(tmpReg)
            tmpregstr = ('|'.join(tmpReg))
            tmpregstr = tmpregstr.replace('"|"', '|')
            if len(tmpregstr) > self.MAX_LEN:
                self.isValTooLong = True

            tmpregstr = regExp % (key, tmpregstr)

        if tmpstr != '' and tmpregstr != '' and isnot:
          return "( %s AND %s )" % (tmpstr, tmpregstr)
        elif tmpstr != '' and tmpregstr != '':
          return "( %s OR %s )" % (tmpstr, tmpregstr)
        elif tmpstr == '':
            return tmpregstr
        else:
            return tmpstr

    def generateNode(self, node, regdicts={}):
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
            return self.applyOverrides(self.generateMapItemNode(node, regdicts))
        elif type(node) in (str, int):
            return self.applyOverrides(self.generateValueNode(node))
        elif type(node) == list:
            return self.applyOverrides(self.generateListNode(node))
        elif isinstance(node, SigmaTypeModifier):
            return self.applyOverrides(self.generateTypedValueNode(node))
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))
        
   #A AND NOT B ---> != 
    def covertToNotValue(self, item, regdicts={}):
        if type(item) == sigma.parser.condition.ConditionAND:
            return self.applyOverrides(self.convertANDToORNode(item))
        elif type(item) == sigma.parser.condition.ConditionOR:
            return self.applyOverrides(self.covertORToANDNode(item))
        elif type(item) == sigma.parser.condition.ConditionNOT:
            return self.applyOverrides(self.generateNode(item))
        elif type(item) == sigma.parser.condition.ConditionNULLValue:
            return self.applyOverrides(self.generateNotNULLValueNode(item))
        elif type(item) == sigma.parser.condition.ConditionNotNULLValue:
            return self.applyOverrides(self.generateNULLValueNode(item))
        elif type(item) == sigma.parser.condition.NodeSubexpression:
            return self.applyOverrides(self.generateNotSubexpressionNode(item))
        elif type(item) == tuple:
            return self.applyOverrides(self.generateMapItemNode(item, regdicts, isnot=True))
        elif type(item) in (str, int):
            return self.applyOverrides(self.generateValueNode(item))
        elif type(item) == list:
            return self.applyOverrides(self.generateListNode(item))
        elif isinstance(item, SigmaTypeModifier):
            return self.applyOverrides(self.generateTypedValueNode(item))
        elif type(item) == sigma.parser.condition.ConditionNOT:
            return self.applyOverrides(self.generateNode(item.item))
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(item))))

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        regDicts = {}
        generated = [ self.generateNode(val, regDicts) for val in node ]

        res = None
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            res = self.orToken.join(filtered)

        if len(regDicts) == 0:
            return res
        else:
            tmp = self.generateRegExpresion(regDicts)
            regDicts.clear()
            if res is None:
                return tmp
            else:
                return res + " OR " + tmp

    def convertANDToORNode(self, node):
        regDicts = {}
        generated = [ self.covertToNotValue(val, regDicts) for val in node ]

        res = None
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            res = self.orToken.join(filtered)

        if len(regDicts) == 0:
            return res
        else:
            tmp = self.generateRegExpresion(regDicts, isnot=True)
            regDicts.clear()
            if res is None:
                return tmp
            else:
                return res + " OR " + tmp

    def covertORToANDNode(self, node):
        generated = [ self.covertToNotValue(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        item = node.item
        generated = self.covertToNotValue(item)
        return generated

    def generateNotSubexpressionNode(self, node):
        generated = self.covertToNotValue(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateValueNode(self, node):
        val = self.cleanValue(str(node))
        if val.find('*') != -1:
            val = self.convertStrToRegstr(val)
        else:
            val = self.convertStrToXmlstr(val)

        return str(self.valueExpression % (val))

    def generateNULLValueNode(self, node):
        interName = self.convertFieldNameToInterAttrName(node.item)
        return self.nullExpression % (interName)

    def generateNotNULLValueNode(self, node):
        interName = self.convertFieldNameToInterAttrName(node.item)
        return self.notNullExpression % (interName)

    def generateRuleHeader(self):
        rulename = "PH_SYS_RULE_THREAT_HUNTING"
        if self.ruleType is None:
            ruleId = "PH_Rule_SIGMA_%d" % (self.ruleIndex)
        else:
            ruleId = "PH_Rule_%s_SIGMA_%d" % (self.ruleType, self.ruleIndex)
 
        f = open(self.ymlFileName, 'r') 
        lines = f.readlines() 
        tags = set()

        for line in lines: 
            match = re.search('^\s*-\s*attack.', line)
            if match is None:
                continue

            index = line.find("an old one")
            if index != -1:
                continue
            line = re.sub("\s*\\n$", '', line)

            tags.add(line)
        f.close()

        technique = []
        for tag in tags:
            tag = re.sub('^\s*-\s*attack\.\s*','', tag)
            match = re.search('(t|T)(\d+\.\d+|\d+)\s*', tag)
            if match is not None:
                tag = tag[1:]
                technique.append("T%s" % tag)
            else:
                match = re.search('\d', tag)
                if match is not None:
                    continue
                tag = re.sub('_',' ', tag).title()
        
        sub_function_str, technique_str= self.formatSubFunctionAndTechniqueId(technique)

        result = None
        if technique_str is not None:
            result = ("<Rule group=\"%s\" natural_id=\"%s\"  phIncidentCategory=\"Server\" function=\"Security\" subFunction=\"%s\" technique=\"%s\">") % (rulename, ruleId, sub_function_str, technique_str)
        else:
            result = ("<Rule group=\"%s\" natural_id=\"%s\"  phIncidentCategory=\"Server\" function=\"Security\" subFunction=\"%s\">") % (rulename, ruleId, sub_function_str)

        return result,ruleId,technique_str

    def generateRuleCommonPart(self, name, description):
        curRuleName = self.formatRuleName(name)
        curTitleName = self.formatRuleTitle(name)

        description = self.convertStrToXmlstr(description)
        filestr = "";
        if self.ymlFileName is not None:
            filestr = "\n  <SigmaFileName> %s </SigmaFileName>" % self.ymlFileName

        tmp = ("\n  <Name>%s </Name>\n  <IncidentTitle>%s</IncidentTitle>\n  <active>true</active>\n  <Description> %s </Description>%s\n  <CustomerScope groupByEachCustomer=\"true\">\n     <Include all=\"true\"/>\n    <Exclude/>\n  </CustomerScope>") % (curRuleName, curTitleName, description, filestr)
        return tmp,curRuleName


    def generateRuleIncidentDef(self, name, level, attrset):
        if level == "low":
            severity = 3
        elif level == "medium":
            severity = 5
        elif level == "high":
            severity = 7
        elif level == "critical":
            severity = 9
        else:
            severity = 1

        title = self.convertStrToXmlstr(name)
        title = title.replace(" ", "_")
        ruleEvtType="PH_RULE_%s" % title
        
        filterStr = set()
        for item in attrset:
            if item == 'eventType':
                filterStr.add('compEventType = Filter.eventType')
            else:
                filterStr.add('%s = Filter.%s' % (item, item))

        filterStr=sorted(filterStr)
        arglist = ",".join(filterStr)
        curFilterAttrs = ",".join(attrset)

        result = ("\n  <IncidentDef eventType=\"%s\" severity=\"%d\">\n    <ArgList> %s </ArgList>\n  </IncidentDef>") % (ruleEvtType, severity, arglist) 
        return result,curFilterAttrs,ruleEvtType
         
    def generateRulePatternClause(self, evtConstrSet, groupByAttrs):
        singleEvtConstr = None
       
        if len(evtConstrSet) > 1:
            evtConstrSet = sorted(evtConstrSet)
            singleEvtConstr = (" OR ".join(['(%s)' % item for item in evtConstrSet]))
        else:
            singleEvtConstr = evtConstrSet.pop() 

        groupByAttr = ",".join(groupByAttrs)

        result = ("\n  <PatternClause window=\"300\">\n    <SubPattern displayName=\"Filter\" name=\"Filter\">\n    <SingleEvtConstr> %s </SingleEvtConstr>\n    <GroupByAttr> %s </GroupByAttr>\n    <GroupEvtConstr> COUNT(*) &gt;= 1 </GroupEvtConstr>\n    </SubPattern>\n    </PatternClause>") % (singleEvtConstr, groupByAttr)

        return result,groupByAttr

    def generateRuleTriggerEventDisplay(self, displayAttrs):
        displayAttrs = sorted(displayAttrs)
        if len(displayAttrs) == 0:
            fields = "phRecvTime,hostName,rawEventMsg"
            return ("\n  <TriggerEventDisplay>\n    <AttrList> %s </AttrList>\n  </TriggerEventDisplay>") % (fields)
        else:
            fields = "phRecvTime,hostName," +  ",".join(displayAttrs) + ",rawEventMsg"
            return ("\n  <TriggerEventDisplay>\n    <AttrList> %s </AttrList>\n  </TriggerEventDisplay>") % (fields)

    def generateRuleTailer(self):
        return "\n</Rule>\n"

    def getDisplayAttr(self, attrset):
        attrset.discard("hostName")
        attrset.discard("eventType")
        attrset.discard("phRecvTime")
        attrset = sorted(attrset)
        return attrset;
    
    def getIncidentDefAttr(self, attrset):
        attrset.add("hostName")
        attrset = sorted(attrset)
        return attrset;

    def getGroupByAttr(self, attrset):    
        attrset.add("hostName")
        attrset = sorted(attrset)
        return attrset

    def toCsvStr(self, val):
        if val is not None and  val.find(",") != -1:
            val = "\"%s\"" % val
        return val

    def generate(self, sigmaparser):

        result = set()

        date = sigmaparser.parsedyaml["date"]
        name = sigmaparser.parsedyaml["title"]    
        des = sigmaparser.parsedyaml["description"]
        level = sigmaparser.parsedyaml["level"]

        res,errMsg = self.generateEvtConstrForOneLogsource(sigmaparser);
        if errMsg is not None:
            print("%s, %s" % (self.ymlFileName, errMsg))
            return None

        result.add(res)
        groupByAttr=copy.deepcopy(self.curAttrs)
        displayAttr=copy.deepcopy(self.curAttrs)
        incidentDefAttr=copy.deepcopy(self.curAttrs)

        groupByAttr = self.getGroupByAttr(groupByAttr)
        displayAttr = self.getDisplayAttr(displayAttr)
        incidentDefAttr = self.getIncidentDefAttr(incidentDefAttr)

        ruleHeader,ruleId,techniques = self.generateRuleHeader()
        ruleCommonPart,curRuleName = self.generateRuleCommonPart(name, des)
        ruleIncidentDef,filterAttrStr,ruleEvtType = self.generateRuleIncidentDef(name, level, incidentDefAttr)
        ruleTriggerEventDisplay = self.generateRuleTriggerEventDisplay(displayAttr)
        ruleTailer = self.generateRuleTailer()
        rulePatternClause,groupByStr = self.generateRulePatternClause(result, groupByAttr)

        result = ruleHeader + ruleCommonPart + ruleIncidentDef + rulePatternClause + ruleTriggerEventDisplay + ruleTailer
        self.ruleIndex += 1
        return result
    
    def setSourceValueForWinServiceApp(self, sigmaparser):
        detection = sigmaparser.parsedyaml.get("detection", None)
        svtSource = set()
        for val in detection.values():
            if isinstance(val,dict):
                for k, v in val.items():
                    if k == "Source":
                        svtSource.add(v)
        svtSource = sorted(svtSource)
        if len(svtSource) == 1:
            self.sourceValueForWinAppEvtTy = svtSource[0]
        else:
            self.sourceValueForWinAppEvtTy = None

    def generateEvtConstrForOneLogsource(self, sigmaparser):
        errMsg = None
        result = None
        self.curAttrs = set()
        self.product = None
        self.service = None
        self.category = None
        self.isValTooLong = False
        logsource = sigmaparser.parsedyaml.get("logsource", None)
        if logsource is not None:
            self.product = logsource.get("product", None)
            self.service = logsource.get("service", None)
            self.category = logsource.get("category", None)

        if self.product == "windows" and ( self.service == "application" or (self.service is None and  self.category == "application")):
            self.setSourceValueForWinServiceApp(sigmaparser) 

        res = set()
        for parsed in sigmaparser.condparsed:
            if self.ymlFileName.find("deprecated/") != -1:
               errMsg = "SKIP RULE (YML is in deprecated directory)"
            elif self.notSupportedLogsource(self.product, self.service):
               errMsg = "SKIP RULE (Logsource in SkipRuleOflogsource.csv)"
            elif self.ymlValidator(parsed.parsedSearch) == False:
                errMsg = "SKIP RULE(Yml format is wrong)"
            if parsed.parsedAgg:
                errMsg = "SKIP RULE (There is an aggregation operator not implemented)"
            else: # generate Event Constr 
                result = self.generateQuery(parsed)
                if result is None:
                    errMsg = "SKIP RULE (There is no single Event Constraint)"
                elif self.isValTooLong:
                    errMsg = "SKIP RULE (Regular expression is too long)"
                else:
                    if self.product == "windows":
                        if result.find('eventType') == -1:
                            errMsg = "SKIP RULE (There is no event type in constraint)"
                            return None, errMsg

                    res.add(result)

        if len(res) == 1:
            result = res.pop()
        else:
            result = " OR ".join(["(%s)"%item for item in res])

        return result,errMsg
