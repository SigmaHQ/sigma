# ee-outliers backend for sigmac
# NVISO (@NVISO_Labs)

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

from .elasticsearch import ElasticsearchDSLBackend
import json
import logging
import configparser
from .mixins import MultiRuleOutputMixin
from io import StringIO


class OutliersBackend(ElasticsearchDSLBackend, MultiRuleOutputMixin):
    """ee-outliers backend"""
    identifier = 'ee-outliers'
    active = True

    def generate(self, sigmaparser):
        super().generate(sigmaparser)

        self.tags = sigmaparser.parsedyaml.setdefault("tags", "")

        if len(self.queries) == 1:
            dsl = json.dumps(self.queries[0])
        else:
            dsl = json.dumps(self.queries)

        self.queries = []

        use_case_name = self.getRuleName(sigmaparser)

        index = ''
        if self.indices is not None and len(self.indices) == 1:
            index = self.indices[0]

        types = ["Sigma hit"]
        types.extend(self.tags)

        config_data = {
            "es_dsl_filter": dsl,
            "es_index": index,
            "outlier_type": ", ".join(types),
            "outlier_reason": "Sigma hit - " + self.title,
            "outlier_summary": "Sigma hit - " + self.title,
            "run_model": 1,
            "test_model": 0
        }

        config = configparser.ConfigParser(interpolation=None)
        config["simplequery_sigma_" + use_case_name] = config_data

        output = StringIO()
        config.write(output)
        result = output.getvalue()
        output.close()

        return result
    
    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        pass
