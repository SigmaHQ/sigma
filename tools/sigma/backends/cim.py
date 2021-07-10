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
                    "cpu_load_percent ": [],
                    "dest": ["ComputerName", "Computer"],
                    "dest_bunit": [],
                    "dest_category": [],
                    "dest_is_expected": [],
                    "dest_priority": [],
                    "dest_requires_av": [],
                    "dest_should_timesync": [],
                    "dest_should_update": [],
                    "mem_used": [],
                    "original_file_name": ["OriginalFileName"],
                    "os": [],
                    "parent_process": ["ParentCommandLine"],
                    "parent_process_exec": [],
                    "parent_process_id": ["ParentProcessId"],
                    "parent_process_guid": ["ParentProcessGuid"],
                    "parent_process_name": [""],
                    "parent_process_path": ["ParentImage"],
                    "process": ["CommandLine"],
                    "process_current_directory": [],
                    "process_exec": [],
                    "process_hash": ["Hashes"],
                    "process_id": ["ProcessId"],
                    "process_guid": ["ProcessGuid"],
                    "process_integrity_level": ["IntegrityLevel"],
                    "process_name": [],
                    "process_path": ["Image"],
                    "tag": [],
                    "user": ["User", "SubjectUserName", "AccountName"],
                    "user_id": ["LogonGuid"],
                    "user_bunit": [],
                    "user_category": [],
                    "user_priority": [],
                    "vendor_product": []
                },
                "mapping": {
                    "category": "process_creation"
                }
            },
            "Filesystem": {
                "fields": {
                    "action": ["EventType"],
                    "dest": ["ComputerName", "Computer"],
                    "dest_bunit": [],
                    "dest_category": [],
                    "dest_priority": [],
                    "dest_requires_av": [],
                    "dest_should_timesync": [],
                    "dest_should_update": [],
                    "file_access_time": [],
                    "file_create_time": ["CreationUtcTime"],
                    "file_hash": ["Hash"],
                    "file_modify_time": [],
                    "file_name": [],
                    "file_path": ["TargetFilename"],
                    "file_acl": [],
                    "file_size": [],
                    "process_id": ["ProcessId"],
                    "process_guid": ["ProcessGuid"],
                    "tag": [],
                    "user": ["User", "SubjectUserName", "AccountName"],
                    "user_bunit": [],
                    "user_category": [],
                    "user_priority": [],
                    "vendor_product": []
                },
                "mapping": {
                    "category": "file_event"
                }
            },
            "Registry": {
                "fields": {
                    "action": ["EventType"],
                    "dest": ["ComputerName", "Computer"],
                    "dest_bunit": [],
                    "dest_category": [],
                    "dest_priority": [],
                    "dest_requires_av": [],
                    "dest_should_timesync": [],
                    "dest_should_update": [],
                    "process_id": ["ProcessId"],
                    "process_guid": ["ProcessGuid"],
                    "registry_hive": [],
                    "registry_path": ["TargetObject"],
                    "registry_key_name": [],
                    "registry_value_data": ["Details"],
                    "registry_value_name": [],
                    "registry_value_text": [],
                    "registry_value_type": [],
                    "status": [],
                    "tag": [],
                    "user": ["User", "SubjectUserName", "AccountName"],
                    "user_bunit": [],
                    "user_category": [],
                    "user_priority": [],
                    "vendor_product": []
                },
                "mapping": {
                    "category": "registry_event"
                }
            }
        }
    }
}
