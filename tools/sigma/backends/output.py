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

import sys

### Output classes
class SingleOutput:
    """
    Single file output

    By default, this opens the given file or stdin and passes everything into this.
    """
    def __init__(self, filename=None):
        if type(filename) == str:
            self.fd = open(filename, "w", encoding='utf-8')
        else:
            self.fd = sys.stdout

    def print(self, *args, **kwargs):
        print(*args, file=self.fd, **kwargs)

    def close(self):
        self.fd.close()
