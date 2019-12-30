# Azure Log Analytics output backend for sigmac
# John Tuckner (@tuckner)

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
import xml.etree.ElementTree as xml

from sigma.backends.ala import AzureLogAnalyticsBackend
from .base import SingleTextQueryBackend
from .data import sysmon_schema
from .exceptions import NotSupportedError

class AzureAPIBackend(AzureLogAnalyticsBackend):
    """Converts Sigma rule into Azure Log Analytics Queries."""
    identifier = "ala-rule"
    active = True
    options = SingleTextQueryBackend.options + (
            ("sysmon", False, "Generate Sysmon event queries for generic rules", None),
            )


    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)


    def create_rule(self, config):
        tags = config.get("tags")
        tactics = list()
        technics = list()
        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[tT][0-9]{4}", tag):
                technics.append(tag.title())
            else:
                if "_" in tag:
                    tag_list = tag.split("_")
                    tag_list = [item.title() for item in tag_list]
                    tactics.append("".join(tag_list))

        rule = {
            "analytics":
                [
                    {
                        "displayName": "{} by {}".format(config.get("title"), config.get('author')),
                        "description": "{} {}".format(config.get("description"), "Technics: {}.".format(",".join(technics))),
                        "severity": config.get("level"),
                        "enabled": True,
                        "query": config.get("translation"),
                        "queryFrequency": "12H",
                        "queryPeriod": "12H",
                        "triggerOperator": "GreaterThan",
                        "triggerThreshold": 1,
                        "suppressionDuration": "12H",
                        "suppressionEnabled": False,
                        "tactics": tactics
                    }
                ]
        }
        return rule

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        configs = sigmaparser.parsedyaml
        configs.update({"translation": translation})
        rule = self.create_rule(configs)
        return rule
