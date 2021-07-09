# Default Datamodel Mappings for SplunkDMBackend

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

default_datamodels = {
    "Endpoint": {
        "datasets": {
            "Processes": {
                "fields": {
                    "action": ["EventType"],
                    "dest": ["ComputerName", "Computer"],
                    "user": ["User", "SubjectUserName", "AccountName"],
                    "user_id": ["LogonGuid"],
                    "process": ["CommandLine"],
                    "process_path": ["Image", "NewProcessName"],
                    "process_id": ["ProcessId"],
                    "process_guid": ["ProcessGuid"],
                    "process_hash": ["Hashes"],
                    "process_current_directory": ["CurrentDirectory"],
                    "parent_process": ["ParentCommandLine"],
                    "parent_process_path": ["ParentImage"],
                    "parent_process_id": ["ParentProcessId"],
                    "parent_process_guid": ["ParentProcessGuid"],
                    "original_file_name": ["OriginalFileName"]
                },
                "mapping": {
                    "category": "process_creation"
                }
            },
            "Filesystem": {
                "fields": {
                    "action": ["EventType"],
                    "dest": ["ComputerName", "Computer"],
                    "user": ["User", "SubjectUserName", "AccountName"],
                    "process_id": ["ProcessId"],
                    "process_guid": ["ProcessGuid"],
                    "file_hash": ["Hash"],
                    "file_create_time": ["CreationUtcTime"],
                    "file_path": ["TargetFilename"]
                },
                "mapping": {
                    "category": "file_event"
                }
            },
            "Registry": {
                "fields": {
                    "action": ["EventType"],
                    "dest": ["ComputerName", "Computer"],
                    "user": ["User", "SubjectUserName", "AccountName"],
                    "process_id": ["ProcessId"],
                    "process_guid": ["ProcessGuid"],
                    "registry_path": ["TargetObject"],
                    "registry_value_data": ["Details"],
                },
                "mapping": {
                    "category": "registry_event"
                }
            }
        }
    }
}
