# Sigma parser
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

# Rule Filtering
class SigmaRuleFilter:
    """Filter for Sigma rules with conditions"""
    LEVELS = {
            "low"      : 0,
            "medium"   : 1,
            "high"     : 2,
            "critical" : 3
            }
    STATES = ["experimental", "testing", "stable"]

    def __init__(self, expr):
        self.minlevel   = None 
        self.maxlevel   = None 
        self.status     = None
        self.logsources = list()
        self.tags       = list()

        for cond in [c.replace(" ", "") for c in expr.split(",")]:
            if cond.startswith("level<="):
                try:
                    level = cond[cond.index("=") + 1:]
                    self.maxlevel = self.LEVELS[level]
                except KeyError as e:
                    raise SigmaRuleFilterParseException("Unknown level '%s' in condition '%s'" % (level, cond)) from e
            elif cond.startswith("level>="):
                try:
                    level = cond[cond.index("=") + 1:]
                    self.minlevel = self.LEVELS[level]
                except KeyError as e:
                    raise SigmaRuleFilterParseException("Unknown level '%s' in condition '%s'" % (level, cond)) from e
            elif cond.startswith("level="):
                try:
                    level = cond[cond.index("=") + 1:]
                    self.minlevel = self.LEVELS[level]
                    self.maxlevel = self.minlevel
                except KeyError as e:
                    raise SigmaRuleFilterParseException("Unknown level '%s' in condition '%s'" % (level, cond)) from e
            elif cond.startswith("status="):
                self.status = cond[cond.index("=") + 1:]
                if self.status not in self.STATES:
                    raise SigmaRuleFilterParseException("Unknown status '%s' in condition '%s'" % (self.status, cond))
            elif cond.startswith("logsource="):
                self.logsources.append(cond[cond.index("=") + 1:])
            elif cond.startswith("tag="):
                self.tags.append(cond[cond.index("=") + 1:].lower())
            else:
                raise SigmaRuleFilterParseException("Unknown condition '%s'" % cond)

    def match(self, yamldoc):
        """Match filter conditions against rule"""
        # Levels
        if self.minlevel is not None or self.maxlevel is not None:
            try:
                level = self.LEVELS[yamldoc['level']]
            except KeyError:    # missing or invalid level
                return False    # User wants level restriction, but it's not possible here

            # Minimum level
            if self.minlevel is not None:
                if level < self.minlevel:
                    return False
            # Maximum level
            if self.maxlevel is not None:
                if level > self.maxlevel:
                    return False

        # Status
        if self.status is not None:
            try:
                status = yamldoc['status']
            except KeyError:    # missing status
                return False    # User wants status restriction, but it's not possible here
            if status != self.status:
                return False

        # Log Sources
        if self.logsources:
            try:
                logsources = { value for key, value in yamldoc['logsource'].items() }
            except (KeyError, AttributeError):    # no log source set
                return False    # User wants status restriction, but it's not possible here

            for logsrc in self.logsources:
                if logsrc not in logsources:
                    return False

        # Tags
        if self.tags:
            try:
                tags = [ tag.lower() for tag in yamldoc['tags']]
            except (KeyError, AttributeError):    # no tags set
                return False

            for tag in self.tags:
                if tag not in tags:
                    return False

        # all tests passed
        return True

class SigmaRuleFilterParseException(Exception):
    pass
