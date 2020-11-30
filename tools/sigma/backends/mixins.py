# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke

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

import sigma

### Mixins
class QuoteCharMixin:
    """
    This class adds the cleanValue method that quotes and filters characters according to the configuration in
    the attributes provided by the mixin.
    """
    reEscape = None                     # match characters that must be quoted
    escapeSubst = "\\\\\g<1>"           # Substitution that is applied to characters/strings matched for escaping by reEscape
    reClear = None                      # match characters that are cleaned out completely

    def cleanValue(self, val):
        if self.reEscape:
            val = self.reEscape.sub(self.escapeSubst, val)
        if self.reClear:
            val = self.reClear.sub("", val)
        return val

class RulenameCommentMixin:
    """Prefixes each rule with the rule title."""
    prefix = "# "
    options = (
            ("rulecomment", False, "Prefix generated query with comment containing title", None),
            )

    def generateBefore(self, parsed):
        if self.rulecomment:
            try:
                return "%s%s\n" % (self.prefix, parsed.sigmaParser.parsedyaml['title'])
            except KeyError:
                return ""

    def generateAfter(self, parsed):
        if self.rulecomment:
            return "\n"

class MultiRuleOutputMixin:
    """Mixin with common for multi-rule outputs"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rulenames = set()

    def getRuleName(self, sigmaparser):
        """
        Generate a rule name from the title of the Sigma rule with following properties:

        * Spaces are replaced with -
        * Unique name by addition of a counter if generated name already in usage

        Generated names are tracked by the Mixin.

        """
        try:
            rulename = sigmaparser.parsedyaml["id"]
        except KeyError:
            rulename = sigmaparser.parsedyaml["title"].replace(" ", "-").replace("(", "").replace(")", "")
        if rulename in self.rulenames:   # add counter if name collides
            cnt = 2
            while "%s-%d" % (rulename, cnt) in self.rulenames:
                cnt += 1
            rulename = "%s-%d" % (rulename, cnt)
        self.rulenames.add(rulename)

        return rulename
