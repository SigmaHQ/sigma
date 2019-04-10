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

# Exceptions
class BackendError(Exception):
    """Base exception for backend-specific errors."""
    pass

class NotSupportedError(BackendError):
    """Exception is raised if some output is required that is not supported by the target language."""
    pass

# Exceptions (backend specific Qualys) - TODO: no backend specific exceptions
class PartialMatchError(Exception):
    pass

class FullMatchError(Exception):
    pass    
