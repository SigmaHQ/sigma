export index_logs__endpoint__winevent__sysmon__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-endpoint-winevent-sysmon-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
export index_logs__endpoint__winevent__powershell__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-endpoint-winevent-powershell-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
export index_logs__endpoint__winevent__wmiactivity__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-endpoint-winevent-wmiactivity-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
export index_logs__endpoint__winevent__system__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-endpoint-winevent-system-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
export index_logs__endpoint__winevent__application__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-endpoint-winevent-application-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
export index_logs__endpoint__winevent__security__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-endpoint-winevent-security-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
export index_logs__X=$(curl -s 'localhost:9200/.kibana/_search?q=index-pattern.title:logs-\*' | jq -r '.hits.hits[0]._id | ltrimstr("index-pattern:")')
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WMI-Persistence---Script-Event-Consumer-File-Write' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects file writes of WMI script event consumer",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WMI Persistence - Script Event Consumer File Write",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"11\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\WINDOWS\\\\\\\\\\\\\\\\system32\\\\\\\\\\\\\\\\wbem\\\\\\\\\\\\\\\\scrcons.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Processes-created-by-MMC' <<EOF
{
  "type": "search",
  "search": {
    "description": "Processes started by MMC could by a sign of lateral movement using MMC application COM object",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Processes created by MMC",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\mmc.exe\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\") AND NOT (command_line:\\\\\"*\\\\\\\\\\\\\\\\RunCmd.cmd\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-TSCON-Start' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a tscon.exe start as LOCAL SYSTEM",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious TSCON Start",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(user:\\\\\"NT AUTHORITY\\\\\\\\\\\\\\\\SYSTEM\\\\\" AND event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\tscon.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Program-Location-with-Network-Connections' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects programs with network connections running in suspicious files system locations",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Program Location with Network Connections",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"3\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\ProgramData\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\$Recycle.bin\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\All Users\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Default\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Public\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Perflogs\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\config\\\\\\\\\\\\\\\\systemprofile\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Fonts\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\IME\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\addins\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Executable-used-by-PlugX-in-Uncommon-Location' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Executable used by PlugX in Uncommon Location",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\CamMute.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Lenovo\\\\\\\\\\\\\\\\Communication Utility\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\chrome_frame_helper.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Google\\\\\\\\\\\\\\\\Chrome\\\\\\\\\\\\\\\\application\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\dvcemumanager.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Microsoft Device Emulator\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Gadget.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Windows Media Player\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\hcc.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\HTML Help Workshop\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\hkcmd.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\System32\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SysNative\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SysWowo64\\\\\\\\*\\\\\"))) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Mc.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Visual Studio*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft SDK*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Kit*\\\\\"))) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\MsMpEng.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Security Client\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Defender\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\AntiMalware\\\\\\\\*\\\\\"))) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\msseces.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Microsoft Security Center\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\OInfoP11.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Common Files\\\\\\\\\\\\\\\\Microsoft Shared\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\OleView.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Visual Studio*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft SDK*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Kit*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Resource Kit\\\\\\\\*\\\\\"))) OR ((event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\OleView.exe\\\\\") AND NOT (event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Visual Studio*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft SDK*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Kit*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Resource Kit\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\*\\\\\")))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Taskmgr-as-LOCAL_SYSTEM' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Taskmgr as LOCAL_SYSTEM",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(user:\\\\\"NT AUTHORITY\\\\\\\\\\\\\\\\SYSTEM\\\\\" AND event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\taskmgr.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Execution-in-Webserver-Root-Folder' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious program execution in a web service root folder (filter out false positives)",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Execution in Webserver Root Folder",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\wwwroot\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wmpub\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\htdocs\\\\\\\\*\\\\\")) AND NOT (process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\services.exe\\\\\") AND process_path:(\\\\\"*bin\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Tools\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SMSComponent\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Exploit-for-CVE-2015-1641' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Winword starting uncommon sub process MicroScMgmt.exe as used in exploits for CVE-2015-1641",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Exploit for CVE-2015-1641",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\WINWORD.EXE\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\MicroScMgmt.exe \\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Windows-Shell-Spawning-Suspicious-Program' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious child process of a Windows shell",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Windows Shell Spawning Suspicious Program",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\mshta.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wmiprvse.exe\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\schtasks.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\nslookup.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bitsadmin.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mshta.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Regsvr32-Anomaly' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects various anomalies in relation to regsvr32.exe",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Regsvr32 Anomaly",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Temp\\\\\\\\*\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*..\\\\\\\\\\\\\\\\..\\\\\\\\\\\\\\\\..\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\regsvr32.exe *\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\EXCEL.EXE\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\/i\\\\\\\\:http* scrobj.dll\\\\\" \\\\\"*\\\\\\\\/i\\\\\\\\:ftp* scrobj.dll\\\\\") AND process_path:\\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\") OR (event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Execution-in-Non-Executable-Folder' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious exection from an uncommon folder",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Execution in Non-Executable Folder",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\$Recycle.bin\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\All Users\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Default\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Public\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Perflogs\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\config\\\\\\\\\\\\\\\\systemprofile\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Fonts\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\IME\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\addins\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:MSHTA-Spawning-Windows-Shell' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a Windows command line executable started from MSHTA.",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: MSHTA Spawning Windows Shell",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\mshta.exe\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\sh.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bash.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\reg.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\BITSADMIN*\\\\\")) AND NOT (command_line:(\\\\\"*\\\\\\\\/HP\\\\\\\\/HP*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\HP\\\\\\\\\\\\\\\\HP*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:UAC-Bypass-via-sdclt' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects changes to HKCU:\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: UAC Bypass via sdclt",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"13\\\\\" AND registry_target_object:\\\\\"HKEY_USERS\\\\\\\\*\\\\\\\\\\\\\\\\Classes\\\\\\\\\\\\\\\\exefile\\\\\\\\\\\\\\\\shell\\\\\\\\\\\\\\\\runas\\\\\\\\\\\\\\\\command\\\\\\\\\\\\\\\\isolatedCommand\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Microsoft-Office-Product-Spawning-Windows-Shell' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Microsoft Office Product Spawning Windows Shell",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\WINWORD.EXE\\\\\" \\\\\"*\\\\\\\\\\\\\\\\EXCEL.EXE\\\\\" \\\\\"*\\\\\\\\\\\\\\\\POWERPNT.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\MSPUB.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\VISIO.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\OUTLOOK.EXE\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\sh.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bash.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\scrcons.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\schtasks.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\hh.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wmic.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mshta.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\msiexec.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-PowerShell-Invocation-based-on-Parent-Process' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious powershell invocations from interpreters or unusual programs",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Suspicious PowerShell Invocation based on Parent Process",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\")) AND NOT (process_current_directory:\\\\\"*\\\\\\\\\\\\\\\\Health Service State\\\\\\\\*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Bitsadmin-Download' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects usage of bitsadmin downloading a file",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Bitsadmin Download",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"\\\\\\\\/transfer\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\bitsadmin.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WSF/JSE/JS/VBA/VBE-File-Execution' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious file execution by wscript and cscript",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: WSF/JSE/JS/VBA/VBE File Execution",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*.jse\\\\\" \\\\\"*.vbe\\\\\" \\\\\"*.js\\\\\" \\\\\"*.vba\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Driver-Load-from-Temp' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detetcs a driver load from a temporary directory",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Driver Load from Temp",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"6\\\\\" AND image_loaded:\\\\\"*\\\\\\\\\\\\\\\\Temp\\\\\\\\*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WScript-or-CScript-Dropper' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects wscript/cscript executions of scripts located in user directories",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: WScript or CScript Dropper",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\*.jse *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\*.vbe *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\*.js *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\*.vba *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\*.vbs *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\ProgramData\\\\\\\\*.jse *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\ProgramData\\\\\\\\*.vbe *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\ProgramData\\\\\\\\*.js *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\ProgramData\\\\\\\\*.vba *\\\\\" \\\\\"* C\\\\\\\\:\\\\\\\\\\\\\\\\ProgramData\\\\\\\\*.vbs *\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Svchost-Process' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious scvhost process start",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Suspicious Svchost Process",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\svchost.exe\\\\\") AND NOT (process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\services.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Malware-Shellcode-in-Verclsid-Target-Process' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detetcs a process access to verclsid.exe that injects shellcode from a Microsoft Office application / VBA macro",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Malware Shellcode in Verclsid Target Process",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(process_granted_access:\\\\\"0x1FFFFF\\\\\" AND event_id:\\\\\"10\\\\\" AND target_process_path:\\\\\"*\\\\\\\\\\\\\\\\verclsid.exe\\\\\") AND ((process_calltrace:\\\\\"*|UNKNOWN*\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\Microsoft Office\\\\\\\\*\\\\\") OR (process_calltrace:\\\\\"*|UNKNOWN\\\\\\\\(*VBE7.DLL*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Shells-Spawned-by-Web-Servers' <<EOF
{
  "type": "search",
  "search": {
    "description": "Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Shells Spawned by Web Servers",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\w3wp.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\httpd.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\nginx.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\php\\\\\\\\-cgi.exe\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\sh.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bash.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Control-Panel-DLL-Load' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Suspicious Control Panel DLL Load",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\rundll32.exe *\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\control.exe\\\\\") AND NOT (command_line:\\\\\"*Shell32.dll*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:cmdkey-Cached-Credentials-Recon' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects usage of cmdkey to look for cached credentials.",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine",
      "user"
    ],
    "hits": 0,
    "title": "Sigma: cmdkey Cached Credentials Recon",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:\\\\\"* \\\\\\\\/list *\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\cmdkey.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-PowerShell-Parameter-Substring' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious PowerShell invocation with a parameter substring",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious PowerShell Parameter Substring",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((process_path:\\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\") AND (\\\\\" \\\\\\\\-windowstyle h \\\\\" OR \\\\\" \\\\\\\\-windowstyl h\\\\\" OR \\\\\" \\\\\\\\-windowsty h\\\\\" OR \\\\\" \\\\\\\\-windowst h\\\\\" OR \\\\\" \\\\\\\\-windows h\\\\\" OR \\\\\" \\\\\\\\-windo h\\\\\" OR \\\\\" \\\\\\\\-wind h\\\\\" OR \\\\\" \\\\\\\\-win h\\\\\" OR \\\\\" \\\\\\\\-wi h\\\\\" OR \\\\\" \\\\\\\\-win h \\\\\" OR \\\\\" \\\\\\\\-win hi \\\\\" OR \\\\\" \\\\\\\\-win hid \\\\\" OR \\\\\" \\\\\\\\-win hidd \\\\\" OR \\\\\" \\\\\\\\-win hidde \\\\\" OR \\\\\" \\\\\\\\-NoPr \\\\\" OR \\\\\" \\\\\\\\-NoPro \\\\\" OR \\\\\" \\\\\\\\-NoProf \\\\\" OR \\\\\" \\\\\\\\-NoProfi \\\\\" OR \\\\\" \\\\\\\\-NoProfil \\\\\" OR \\\\\" \\\\\\\\-nonin \\\\\" OR \\\\\" \\\\\\\\-nonint \\\\\" OR \\\\\" \\\\\\\\-noninte \\\\\" OR \\\\\" \\\\\\\\-noninter \\\\\" OR \\\\\" \\\\\\\\-nonintera \\\\\" OR \\\\\" \\\\\\\\-noninterac \\\\\" OR \\\\\" \\\\\\\\-noninteract \\\\\" OR \\\\\" \\\\\\\\-noninteracti \\\\\" OR \\\\\" \\\\\\\\-noninteractiv \\\\\" OR \\\\\" \\\\\\\\-ec \\\\\" OR \\\\\" \\\\\\\\-encodedComman \\\\\" OR \\\\\" \\\\\\\\-encodedComma \\\\\" OR \\\\\" \\\\\\\\-encodedComm \\\\\" OR \\\\\" \\\\\\\\-encodedCom \\\\\" OR \\\\\" \\\\\\\\-encodedCo \\\\\" OR \\\\\" \\\\\\\\-encodedC \\\\\" OR \\\\\" \\\\\\\\-encoded \\\\\" OR \\\\\" \\\\\\\\-encode \\\\\" OR \\\\\" \\\\\\\\-encod \\\\\" OR \\\\\" \\\\\\\\-enco \\\\\" OR \\\\\" \\\\\\\\-en \\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Typical-Malware-Back-Connect-Ports' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects programs that connect to typical malware back connetc ports based on statistical analysis from two different sandbox system databases",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Typical Malware Back Connect Ports",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"3\\\\\" AND dst_port_number:(\\\\\"4443\\\\\" \\\\\"2448\\\\\" \\\\\"8143\\\\\" \\\\\"1777\\\\\" \\\\\"1443\\\\\" \\\\\"243\\\\\" \\\\\"65535\\\\\" \\\\\"13506\\\\\" \\\\\"3360\\\\\" \\\\\"200\\\\\" \\\\\"198\\\\\" \\\\\"49180\\\\\" \\\\\"13507\\\\\" \\\\\"6625\\\\\" \\\\\"4444\\\\\" \\\\\"4438\\\\\" \\\\\"1904\\\\\" \\\\\"13505\\\\\" \\\\\"13504\\\\\" \\\\\"12102\\\\\" \\\\\"9631\\\\\" \\\\\"5445\\\\\" \\\\\"2443\\\\\" \\\\\"777\\\\\" \\\\\"13394\\\\\" \\\\\"13145\\\\\" \\\\\"12103\\\\\" \\\\\"5552\\\\\" \\\\\"3939\\\\\" \\\\\"3675\\\\\" \\\\\"666\\\\\" \\\\\"473\\\\\" \\\\\"5649\\\\\" \\\\\"4455\\\\\" \\\\\"4433\\\\\" \\\\\"1817\\\\\" \\\\\"100\\\\\" \\\\\"65520\\\\\" \\\\\"1960\\\\\" \\\\\"1515\\\\\" \\\\\"743\\\\\" \\\\\"700\\\\\" \\\\\"14154\\\\\" \\\\\"14103\\\\\" \\\\\"14102\\\\\" \\\\\"12322\\\\\" \\\\\"10101\\\\\" \\\\\"7210\\\\\" \\\\\"4040\\\\\" \\\\\"9943\\\\\")) AND NOT (process_path:\\\\\"*\\\\\\\\\\\\\\\\Program Files*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Password-Dumper-Remote-Thread-in-LSASS' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundrets of events.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Password Dumper Remote Thread in LSASS",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"8\\\\\" AND target_process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\lsass.exe\\\\\" AND NOT _exists_:thread_startmodule)\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WMI-Persistence---Command-Line-Event-Consumer' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WMI command line event consumers",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WMI Persistence - Command Line Event Consumer",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"7\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\wbem\\\\\\\\\\\\\\\\WmiPrvSE.exe\\\\\" AND image_loaded:\\\\\"wbemcons.dll\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PowerShell-Network-Connections' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detetcs a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company's ip range')",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: PowerShell Network Connections",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"3\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\") AND NOT (dst_isipv6:\\\\\"false\\\\\" AND user:\\\\\"NT AUTHORITY\\\\\\\\\\\\\\\\SYSTEM\\\\\" AND dst_ip:(\\\\\"10.*\\\\\" \\\\\"192.168.*\\\\\" \\\\\"172.*\\\\\" \\\\\"127.0.0.1\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:New-RUN-Key-Pointing-to-Suspicious-Folder' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious new RUN key element pointing to an executable in a suspicious folder",
    "version": 1,
    "columns": [
      "process_path"
    ],
    "hits": 0,
    "title": "Sigma: New RUN Key Pointing to Suspicious Folder",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"13\\\\\" AND registry_details:(\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Temp\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\$Recycle.bin\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Temp\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Public\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Default\\\\\\\\*\\\\\") AND registry_target_object:\\\\\"\\\\\\\\\\\\\\\\REGISTRY\\\\\\\\\\\\\\\\MACHINE\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Run\\\\\\\\*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Taskmgr-as-Parent' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the creation of a process from Windows task manager",
    "version": 1,
    "columns": [
      "process_path",
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Taskmgr as Parent",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\taskmgr.exe\\\\\") AND NOT (process_path:(\\\\\"resmon.exe\\\\\" \\\\\"mmc.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Sticky-Key-Like-Backdoor-Usage' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Sticky Key Like Backdoor Usage",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\cmd.exe sethc.exe *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cmd.exe utilman.exe *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cmd.exe osk.exe *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cmd.exe Magnify.exe *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cmd.exe Narrator.exe *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cmd.exe DisplaySwitch.exe *\\\\\") AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\winlogon.exe\\\\\")) OR (event_id:\\\\\"13\\\\\" AND registry_target_object:(\\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\\\\\\\\\sethc.exe\\\\\\\\\\\\\\\\Debugger\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\\\\\\\\\utilman.exe\\\\\\\\\\\\\\\\Debugger\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\\\\\\\\\osk.exe\\\\\\\\\\\\\\\\Debugger\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\\\\\\\\\Magnify.exe\\\\\\\\\\\\\\\\Debugger\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\\\\\\\\\Narrator.exe\\\\\\\\\\\\\\\\Debugger\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\\\\\\\\\DisplaySwitch.exe\\\\\\\\\\\\\\\\Debugger\\\\\") AND registry_event_type:\\\\\"SetValue\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Command-Line-Execution-with-suspicious-URL-and-AppData-Strings' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Command Line Execution with suspicious URL and AppData Strings",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"cmd.exe \\\\\\\\/c *http\\\\\\\\:\\\\\\\\/\\\\\\\\/*%AppData%\\\\\" \\\\\"cmd.exe \\\\\\\\/c *https\\\\\\\\:\\\\\\\\/\\\\\\\\/*%AppData%\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:DHCP-Callout-DLL-installation' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: DHCP Callout DLL installation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"13\\\\\" AND registry_target_object:(\\\\\"*\\\\\\\\\\\\\\\\Services\\\\\\\\\\\\\\\\DHCPServer\\\\\\\\\\\\\\\\Parameters\\\\\\\\\\\\\\\\CalloutDlls\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Services\\\\\\\\\\\\\\\\DHCPServer\\\\\\\\\\\\\\\\Parameters\\\\\\\\\\\\\\\\CalloutEnabled\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Office-Macro-Starts-Cmd' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a Windows command line executable started from Microsoft Word or Excel",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Office Macro Starts Cmd",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\WINWORD.EXE\\\\\" \\\\\"*\\\\\\\\\\\\\\\\EXCEL.EXE\\\\\") AND process_path:\\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:SquiblyTwo' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: SquiblyTwo",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"wmic * *format\\\\\\\\:\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"http*\\\\\" \\\\\"wmic * \\\\\\\\/format\\\\\\\\:'http\\\\\" \\\\\"wmic * \\\\\\\\/format\\\\\\\\:http*\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\wmic.exe\\\\\")) OR (Imphash:(\\\\\"1B1A3F43BF37B5BFE60751F2EE2F326E\\\\\" \\\\\"37777A96245A3C74EB217308F3546F4C\\\\\" \\\\\"9D87C9D67CE724033C0B40CC4CA1B206\\\\\") AND event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"* *format\\\\\\\\:\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"http*\\\\\" \\\\\"* \\\\\\\\/format\\\\\\\\:'http\\\\\" \\\\\"* \\\\\\\\/format\\\\\\\\:http*\\\\\")))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Registry-Persistence-Mechanisms' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects persistence registry keys",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Registry Persistence Mechanisms",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"13\\\\\" AND registry_target_object:(\\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Image File Execution Options\\\\\\\\*\\\\\\\\\\\\\\\\GlobalFlag\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\SilentProcessExit\\\\\\\\*\\\\\\\\\\\\\\\\ReportingMode\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows NT\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\SilentProcessExit\\\\\\\\*\\\\\\\\\\\\\\\\MonitorProcess\\\\\") AND registry_event_type:\\\\\"SetValue\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Webshell-Detection-With-Command-Line-Keywords' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects certain command line parameters often used during reconnissaince activity via web shells",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Webshell Detection With Command Line Keywords",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"whoami\\\\\" \\\\\"net user\\\\\" \\\\\"ping \\\\\\\\-n\\\\\" \\\\\"systeminfo\\\\\") AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\apache*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\tomcat*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\w3wp.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\php\\\\\\\\-cgi.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\nginx.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\httpd.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Microsoft-Binary-Github-Communication' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects an executable in the Windows folder accessing github.com",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Microsoft Binary Github Communication",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(dst_host:\\\\\"*.github.com\\\\\" AND event_id:\\\\\"3\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Rundll32-Internet-Connection' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a rundll32 that communicates with piblic IP addresses",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Rundll32 Internet Connection",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"3\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\rundll32.exe\\\\\") AND NOT (dst_ip:(\\\\\"10.*\\\\\" \\\\\"192.168.*\\\\\" \\\\\"172.*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:QuarksPwDump-Dump-File' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a dump file written by QuarksPwDump password dumper",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: QuarksPwDump Dump File",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"11\\\\\" AND file_name:\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Local\\\\\\\\\\\\\\\\Temp\\\\\\\\\\\\\\\\SAM\\\\\\\\-*.dmp*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Ping-Hex-IP' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a ping command that uses a hex encoded IP address",
    "version": 1,
    "columns": [
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Ping Hex IP",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\ping.exe 0x*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\ping 0x*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PowerShell-Download-from-URL' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detetcs a Powershell process that contains download commands in its command line string",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: PowerShell Download from URL",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*new\\\\\\\\-object system.net.webclient\\\\\\\\).downloadstring\\\\\\\\(*\\\\\" \\\\\"*new\\\\\\\\-object system.net.webclient\\\\\\\\).downloadfile\\\\\\\\(*\\\\\") AND process_path:\\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Exploit-for-CVE-2017-0261' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Winword starting uncommon sub process FLTLDR.exe as used in exploits for CVE-2017-0261 and CVE-2017-0262",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Exploit for CVE-2017-0261",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\WINWORD.EXE\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\FLTLDR.exe*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:System-File-Execution-Location-Anomaly' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a Windows program executable started in a suspicious folder",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: System File Execution Location Anomaly",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\svchost.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\services.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\spoolsv.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\lsass.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\smss.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\csrss.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\conhost.exe\\\\\")) AND NOT (process_path:(\\\\\"*\\\\\\\\\\\\\\\\System32\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SysWow64\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Reconnaissance-Activity' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious command line activity on Windows systems",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Suspicious Reconnaissance Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"net group \\\\\\\\\\\\\"domain admins\\\\\\\\\\\\\" \\\\\\\\/domain\\\\\" \\\\\"net localgroup administrators\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Java-Running-with-Remote-Debugging' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detcts a JAVA process running with remote debugging allowing more than just localhost to connect",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Java Running with Remote Debugging",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*transport\\\\\\\\=dt_socket,address\\\\\\\\=*\\\\\") AND NOT (command_line:\\\\\"*address\\\\\\\\=127.0.0.1*\\\\\" OR command_line:\\\\\"*address\\\\\\\\=localhost*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Malicious-Named-Pipe' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the creation of a named pipe used by known APT malware",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Malicious Named Pipe",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"17\\\\\" \\\\\"18\\\\\") AND pipe_name:(\\\\\"\\\\\\\\\\\\\\\\isapi_http\\\\\" \\\\\"\\\\\\\\\\\\\\\\isapi_dg\\\\\" \\\\\"\\\\\\\\\\\\\\\\isapi_dg2\\\\\" \\\\\"\\\\\\\\\\\\\\\\sdlrpc\\\\\" \\\\\"\\\\\\\\\\\\\\\\ahexec\\\\\" \\\\\"\\\\\\\\\\\\\\\\winsession\\\\\" \\\\\"\\\\\\\\\\\\\\\\lsassw\\\\\" \\\\\"\\\\\\\\\\\\\\\\46a676ab7f179e511e30dd2dc41bd388\\\\\" \\\\\"\\\\\\\\\\\\\\\\9f81f59bc58452127884ce513865ed20\\\\\" \\\\\"\\\\\\\\\\\\\\\\e710f28d59aa529d6792ca6ff0ca1b34\\\\\" \\\\\"\\\\\\\\\\\\\\\\rpchlp_3\\\\\" \\\\\"\\\\\\\\\\\\\\\\NamePipe_MoreWindows\\\\\" \\\\\"\\\\\\\\\\\\\\\\pcheap_reuse\\\\\" \\\\\"\\\\\\\\\\\\\\\\NamePipe_MoreWindows\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Certutil-Command' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detetcs a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Suspicious Certutil Command",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\certutil.exe * \\\\\\\\-decode *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe * \\\\\\\\-decodehex *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe *\\\\\\\\-urlcache* http*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe *\\\\\\\\-urlcache* ftp*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe *\\\\\\\\-URL*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe *\\\\\\\\-ping*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Scheduled-Task-Creation' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the creation of scheduled tasks in user session",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Scheduled Task Creation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:\\\\\"* \\\\\\\\/create *\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\schtasks.exe\\\\\") AND NOT (user:\\\\\"NT AUTHORITY\\\\\\\\\\\\\\\\SYSTEM\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Activity-Related-to-NTDS.dit-Domain-Hash-Retrieval' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Activity Related to NTDS.dit Domain Hash Retrieval",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"vssadmin.exe Delete Shadows\\\\\" \\\\\"vssadmin create shadow \\\\\\\\/for\\\\\\\\=C\\\\\\\\:\\\\\" \\\\\"copy \\\\\\\\\\\\\\\\\\\\\\\\?\\\\\\\\\\\\\\\\GLOBALROOT\\\\\\\\\\\\\\\\Device\\\\\\\\*\\\\\\\\\\\\\\\\windows\\\\\\\\\\\\\\\\ntds\\\\\\\\\\\\\\\\ntds.dit\\\\\" \\\\\"copy \\\\\\\\\\\\\\\\\\\\\\\\?\\\\\\\\\\\\\\\\GLOBALROOT\\\\\\\\\\\\\\\\Device\\\\\\\\*\\\\\\\\\\\\\\\\config\\\\\\\\\\\\\\\\SAM\\\\\" \\\\\"vssadmin delete shadows \\\\\\\\/for\\\\\\\\=C\\\\\\\\:\\\\\" \\\\\"reg SAVE HKLM\\\\\\\\\\\\\\\\SYSTEM \\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Mimikatz-In-Memory' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects certain DLL loads when Mimikatz gets executed",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Mimikatz In-Memory",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"7\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\rundll32.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-WMI-execution' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WMI executing suspicious commands",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Suspicious WMI execution",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\/NODE\\\\\\\\:*process call create *\\\\\" \\\\\"* path AntiVirusProduct get *\\\\\" \\\\\"* path FirewallProduct get *\\\\\" \\\\\"* shadowcopy delete *\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\wmic.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:UAC-Bypass-via-Event-Viewer' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects UAC bypass method using Windows event viewer",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: UAC Bypass via Event Viewer",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"13\\\\\" AND registry_target_object:\\\\\"HKEY_USERS\\\\\\\\*\\\\\\\\\\\\\\\\mscfile\\\\\\\\\\\\\\\\shell\\\\\\\\\\\\\\\\open\\\\\\\\\\\\\\\\command\\\\\") OR ((event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\eventvwr.exe\\\\\") AND NOT (process_path:\\\\\"*\\\\\\\\\\\\\\\\mmc.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Microsoft-Outlook-Spawning-Windows-Shell' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a Windows command line executable started from Microsoft Outlook",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Microsoft Outlook Spawning Windows Shell",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:(\\\\\"*\\\\\\\\\\\\\\\\OUTLOOK.EXE\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\cmd.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\powershell.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\sh.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bash.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\schtasks.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Net.exe-Execution' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects execution of Net.exe, whether suspicious or benign.",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: Net.exe Execution",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"* group*\\\\\" \\\\\"* localgroup*\\\\\" \\\\\"* user*\\\\\" \\\\\"* view*\\\\\" \\\\\"* share\\\\\" \\\\\"* accounts*\\\\\" \\\\\"* use*\\\\\") AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\net.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\net1.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:DNS-ServerLevelPluginDll-Install' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)",
    "version": 1,
    "columns": [
      "event_id",
      "command_line",
      "ParentCommandLine",
      "process_path",
      "user",
      "registry_target_object"
    ],
    "hits": 0,
    "title": "Sigma: DNS ServerLevelPluginDll Install",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"13\\\\\" AND registry_target_object:\\\\\"*\\\\\\\\\\\\\\\\services\\\\\\\\\\\\\\\\DNS\\\\\\\\\\\\\\\\Parameters\\\\\\\\\\\\\\\\ServerLevelPluginDll\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:\\\\\"dnscmd.exe \\\\\\\\/config \\\\\\\\/serverlevelplugindll *\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Executables-Started-in-Suspicious-Folder' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects process starts of binaries from a suspicious folder",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Executables Started in Suspicious Folder",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\PerfLogs\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\$Recycle.bin\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Intel\\\\\\\\\\\\\\\\Logs\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Default\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\Public\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Users\\\\\\\\\\\\\\\\NetworkService\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Fonts\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Debug\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Media\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\Help\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\addins\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\repair\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\security\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\RSA\\\\\\\\\\\\\\\\MachineKeys\\\\\\\\*\\\\\" \\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\system32\\\\\\\\\\\\\\\\config\\\\\\\\\\\\\\\\systemprofile\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-RDP-Redirect-Using-TSCON' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious RDP session redirect using tscon.exe",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious RDP Redirect Using TSCON",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:\\\\\"* \\\\\\\\/dest\\\\\\\\:rdp\\\\\\\\-tcp\\\\\\\\:*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-RDP-Redirect-Using-TSCON-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a suspicious RDP session redirect using tscon.exe",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious RDP Redirect Using TSCON",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"* \\\\\\\\/dest\\\\\\\\:rdp\\\\\\\\-tcp\\\\\\\\:*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Exploit-for-CVE-2017-8759' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Winword starting uncommon sub process csc.exe as used in exploits for CVE-2017-8759",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Exploit for CVE-2017-8759",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\WINWORD.EXE\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\csc.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Droppers-exploiting-CVE-2017-11882' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects exploits that use CVE-2017-11882 to start EQNEDT32.EXE and other sub processes like mshta.exe",
    "version": 1,
    "columns": [
      "command_line"
    ],
    "hits": 0,
    "title": "Sigma: Droppers exploiting CVE-2017-11882",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"*\\\\\\\\\\\\\\\\EQNEDT32.EXE\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Mimikatz-Detection-LSASS-Access' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects process access to LSASS which is typical for Mimikatz (0x1000 PROCESS_QUERY_ LIMITED_INFORMATION, 0x0400 PROCESS_QUERY_ INFORMATION, 0x0010 PROCESS_VM_READ)",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Mimikatz Detection LSASS Access",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(process_granted_access:\\\\\"0x1410\\\\\" AND event_id:\\\\\"10\\\\\" AND target_process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\windows\\\\\\\\\\\\\\\\system32\\\\\\\\\\\\\\\\lsass.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Reconnaissance-Activity' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects activity as \"net user administrator /domain\" and \"net group domain admins /domain\"",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Reconnaissance Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4661\\\\\" AND object_access_mask_requested:\\\\\"0x2d\\\\\" AND object_type:\\\\\"SAM_USER\\\\\" AND object_name:\\\\\"S\\\\\\\\-1\\\\\\\\-5\\\\\\\\-21\\\\\\\\-*\\\\\\\\-500\\\\\" OR event_id:\\\\\"4661\\\\\" AND object_access_mask_requested:\\\\\"0x2d\\\\\" AND object_type:\\\\\"SAM_GROUP\\\\\" AND object_name:\\\\\"S\\\\\\\\-1\\\\\\\\-5\\\\\\\\-21\\\\\\\\-*\\\\\\\\-512\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:smbexec.py-Service-Installation' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the use of smbexec.py tool by detecting a specific service installation",
    "version": 1,
    "columns": [
      "service_name",
      "service_image_path"
    ],
    "hits": 0,
    "title": "Sigma: smbexec.py Service Installation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"7045\\\\\" AND service_name:\\\\\"BTOBTO\\\\\" AND service_image_path:\\\\\"*\\\\\\\\\\\\\\\\execute.bat\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:DHCP-Server-Loaded-the-CallOut-DLL' <<EOF
{
  "type": "search",
  "search": {
    "description": "This rule detects a DHCP server in which a specified Callout DLL (in registry) was loaded",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: DHCP Server Loaded the CallOut DLL",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1033\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:SAM-Dump-to-AppData' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: SAM Dump to AppData",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"16\\\\\") AND (\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Local\\\\\\\\\\\\\\\\Temp\\\\\\\\\\\\\\\\SAM\\\\\\\\-*.dmp *\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Successful-Overpass-the-Hash-Attempt' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Successful Overpass the Hash Attempt",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(logon_type:\\\\\"9\\\\\" AND logon_authentication_package:\\\\\"Negotiate\\\\\" AND event_id:\\\\\"4624\\\\\" AND logon_process_name:\\\\\"seclogo\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Quick-Execution-of-a-Series-of-Suspicious-Commands' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects multiple suspicious process in a limited timeframe",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Quick Execution of a Series of Suspicious Commands",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"arp.exe\\\\\" \\\\\"at.exe\\\\\" \\\\\"attrib.exe\\\\\" \\\\\"cscript.exe\\\\\" \\\\\"dsquery.exe\\\\\" \\\\\"hostname.exe\\\\\" \\\\\"ipconfig.exe\\\\\" \\\\\"mimikatz.exe\\\\\" \\\\\"nbstat.exe\\\\\" \\\\\"net.exe\\\\\" \\\\\"netsh.exe\\\\\" \\\\\"nslookup.exe\\\\\" \\\\\"ping.exe\\\\\" \\\\\"quser.exe\\\\\" \\\\\"qwinsta.exe\\\\\" \\\\\"reg.exe\\\\\" \\\\\"runas.exe\\\\\" \\\\\"sc.exe\\\\\" \\\\\"schtasks.exe\\\\\" \\\\\"ssh.exe\\\\\" \\\\\"systeminfo.exe\\\\\" \\\\\"taskkill.exe\\\\\" \\\\\"telnet.exe\\\\\" \\\\\"tracert.exe\\\\\" \\\\\"wscript.exe\\\\\" \\\\\"xcopy.exe\\\\\" \\\\\"pscp.exe\\\\\" \\\\\"copy.exe\\\\\" \\\\\"robocopy.exe\\\\\" \\\\\"certutil.exe\\\\\" \\\\\"vssadmin.exe\\\\\" \\\\\"powershell.exe\\\\\" \\\\\"wevtutil.exe\\\\\" \\\\\"psexec.exe\\\\\" \\\\\"bcedit.exe\\\\\" \\\\\"wbadmin.exe\\\\\" \\\\\"icacls.exe\\\\\" \\\\\"diskpart.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Quick-Execution-of-a-Series-of-Suspicious-Commands-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects multiple suspicious process in a limited timeframe",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Quick Execution of a Series of Suspicious Commands",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"arp.exe\\\\\" \\\\\"at.exe\\\\\" \\\\\"attrib.exe\\\\\" \\\\\"cscript.exe\\\\\" \\\\\"dsquery.exe\\\\\" \\\\\"hostname.exe\\\\\" \\\\\"ipconfig.exe\\\\\" \\\\\"mimikatz.exe\\\\\" \\\\\"nbstat.exe\\\\\" \\\\\"net.exe\\\\\" \\\\\"netsh.exe\\\\\" \\\\\"nslookup.exe\\\\\" \\\\\"ping.exe\\\\\" \\\\\"quser.exe\\\\\" \\\\\"qwinsta.exe\\\\\" \\\\\"reg.exe\\\\\" \\\\\"runas.exe\\\\\" \\\\\"sc.exe\\\\\" \\\\\"schtasks.exe\\\\\" \\\\\"ssh.exe\\\\\" \\\\\"systeminfo.exe\\\\\" \\\\\"taskkill.exe\\\\\" \\\\\"telnet.exe\\\\\" \\\\\"tracert.exe\\\\\" \\\\\"wscript.exe\\\\\" \\\\\"xcopy.exe\\\\\" \\\\\"pscp.exe\\\\\" \\\\\"copy.exe\\\\\" \\\\\"robocopy.exe\\\\\" \\\\\"certutil.exe\\\\\" \\\\\"vssadmin.exe\\\\\" \\\\\"powershell.exe\\\\\" \\\\\"wevtutil.exe\\\\\" \\\\\"psexec.exe\\\\\" \\\\\"bcedit.exe\\\\\" \\\\\"wbadmin.exe\\\\\" \\\\\"icacls.exe\\\\\" \\\\\"diskpart.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Disabling-Windows-Event-Auditing' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off \"Local Group Policy Object Processing\" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as \"gpedit.msc\". Please note, that disabling \"Local Group Policy Object Processing\" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.\n",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Disabling Windows Event Auditing",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4719\\\\\" AND policy_changes:\\\\\"removed\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Access-to-ADMIN$-Share' <<EOF
{
  "type": "search",
  "search": {
    "description": null,
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Access to ADMIN$ Share",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"5140\\\\\" AND share_name:\\\\\"Admin$\\\\\") AND NOT (user_name:\\\\\"*$\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Malicious-Service-Installations' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Malicious Service Installations",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"7045\\\\\") AND ((service_image_path:\\\\\"* net user *\\\\\") OR (service_image_path:\\\\\"*\\\\\\\\\\\\\\\\PAExec*\\\\\") OR (service_image_path:\\\\\"winexesvc.exe*\\\\\") OR (service_name:\\\\\"mssecsvc2.0\\\\\") OR (service_name:(\\\\\"WCESERVICE\\\\\" \\\\\"WCE SERVICE\\\\\")) OR (service_name:(\\\\\"pwdump*\\\\\" \\\\\"gsecdump*\\\\\" \\\\\"cachedump*\\\\\")) OR (service_image_path:\\\\\"*\\\\\\\\\\\\\\\\DumpSvc.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Multiple-Failed-Logins-with-Different-Accounts-from-Single-Source-System' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious failed logins with different user accounts from a single source system",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Multiple Failed Logins with Different Accounts from Single Source System",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"529\\\\\" \\\\\"4625\\\\\") AND _exists_:src_host AND _exists_:user_name)\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Multiple-Failed-Logins-with-Different-Accounts-from-Single-Source-System' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious failed logins with different user accounts from a single source system",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Multiple Failed Logins with Different Accounts from Single Source System",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4776\\\\\" AND _exists_:src_host AND _exists_:user_name)\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Reconnaissance-Activity-with-Net-Command' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a set of commands often used in recon stages by different attack groups",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Reconnaissance Activity with Net Command",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"tasklist\\\\\" \\\\\"net time\\\\\" \\\\\"systeminfo\\\\\" \\\\\"whoami\\\\\" \\\\\"nbtstat\\\\\" \\\\\"net start\\\\\" \\\\\"*\\\\\\\\\\\\\\\\net1 start\\\\\" \\\\\"qprocess\\\\\" \\\\\"nslookup\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Reconnaissance-Activity-with-Net-Command-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a set of commands often used in recon stages by different attack groups",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Reconnaissance Activity with Net Command",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"tasklist\\\\\" \\\\\"net time\\\\\" \\\\\"systeminfo\\\\\" \\\\\"whoami\\\\\" \\\\\"nbtstat\\\\\" \\\\\"net start\\\\\" \\\\\"*\\\\\\\\\\\\\\\\net1 start\\\\\" \\\\\"qprocess\\\\\" \\\\\"nslookup\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Enabled-User-Right-in-AD-to-Control-User-Objects' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Enabled User Right in AD to Control User Objects",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4707\\\\\") AND (\\\\\"SeEnableDelegationPrivilege\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Malicious-Service-Install' <<EOF
{
  "type": "search",
  "search": {
    "description": "This method detects well-known keywords of malicious services in the Windows System Eventlog",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Malicious Service Install",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:(\\\\\"7045\\\\\" \\\\\"4697\\\\\")) AND (\\\\\"WCE SERVICE\\\\\" OR \\\\\"WCESERVICE\\\\\" OR \\\\\"DumpSvc\\\\\")) OR (event_id:\\\\\"16\\\\\" AND hive_name:\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Local\\\\\\\\\\\\\\\\Temp\\\\\\\\\\\\\\\\SAM*.dmp\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Process-Creation' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process starts on Windows systems bsed on keywords",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Process Creation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"vssadmin.exe delete shadows*\\\\\" \\\\\"vssadmin delete shadows*\\\\\" \\\\\"vssadmin create shadow \\\\\\\\/for\\\\\\\\=C\\\\\\\\:*\\\\\" \\\\\"copy \\\\\\\\\\\\\\\\\\\\\\\\?\\\\\\\\\\\\\\\\GLOBALROOT\\\\\\\\\\\\\\\\Device\\\\\\\\*\\\\\\\\\\\\\\\\windows\\\\\\\\\\\\\\\\ntds\\\\\\\\\\\\\\\\ntds.dit*\\\\\" \\\\\"copy \\\\\\\\\\\\\\\\\\\\\\\\?\\\\\\\\\\\\\\\\GLOBALROOT\\\\\\\\\\\\\\\\Device\\\\\\\\*\\\\\\\\\\\\\\\\config\\\\\\\\\\\\\\\\SAM*\\\\\" \\\\\"reg SAVE HKLM\\\\\\\\\\\\\\\\SYSTEM *\\\\\" \\\\\"* sekurlsa\\\\\\\\:*\\\\\" \\\\\"net localgroup adminstrators * \\\\\\\\/add\\\\\" \\\\\"net group \\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\" * \\\\\\\\/ADD \\\\\\\\/DOMAIN\\\\\" \\\\\"certutil.exe *\\\\\\\\-urlcache* http*\\\\\" \\\\\"certutil.exe *\\\\\\\\-urlcache* ftp*\\\\\" \\\\\"netsh advfirewall firewall *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"attrib \\\\\\\\+S \\\\\\\\+H \\\\\\\\+R *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"schtasks* \\\\\\\\/create *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"schtasks* \\\\\\\\/sc minute*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Regasm.exe *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Regasm *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bitsadmin* \\\\\\\\/transfer*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe * \\\\\\\\-decode *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe * \\\\\\\\-decodehex *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe \\\\\\\\-ping *\\\\\" \\\\\"icacls * \\\\\\\\/grant Everyone\\\\\\\\:F \\\\\\\\/T \\\\\\\\/C \\\\\\\\/Q\\\\\" \\\\\"* wmic shadowcopy delete *\\\\\" \\\\\"* wbadmin.exe delete catalog \\\\\\\\-quiet*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.jse\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.js\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.vba\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.vbe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.jse\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.js\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.vba\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.vbe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\fodhelper.exe\\\\\" \\\\\"*waitfor*\\\\\\\\/s*\\\\\" \\\\\"*waitfor*\\\\\\\\/si persist*\\\\\" \\\\\"*remote*\\\\\\\\/s*\\\\\" \\\\\"*remote*\\\\\\\\/c*\\\\\" \\\\\"*remote*\\\\\\\\/q*\\\\\" \\\\\"*AddInProcess*\\\\\" \\\\\"*msbuild*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Process-Creation-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process starts on Windows systems bsed on keywords",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Process Creation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"vssadmin.exe delete shadows*\\\\\" \\\\\"vssadmin delete shadows*\\\\\" \\\\\"vssadmin create shadow \\\\\\\\/for\\\\\\\\=C\\\\\\\\:*\\\\\" \\\\\"copy \\\\\\\\\\\\\\\\\\\\\\\\?\\\\\\\\\\\\\\\\GLOBALROOT\\\\\\\\\\\\\\\\Device\\\\\\\\*\\\\\\\\\\\\\\\\windows\\\\\\\\\\\\\\\\ntds\\\\\\\\\\\\\\\\ntds.dit*\\\\\" \\\\\"copy \\\\\\\\\\\\\\\\\\\\\\\\?\\\\\\\\\\\\\\\\GLOBALROOT\\\\\\\\\\\\\\\\Device\\\\\\\\*\\\\\\\\\\\\\\\\config\\\\\\\\\\\\\\\\SAM*\\\\\" \\\\\"reg SAVE HKLM\\\\\\\\\\\\\\\\SYSTEM *\\\\\" \\\\\"* sekurlsa\\\\\\\\:*\\\\\" \\\\\"net localgroup adminstrators * \\\\\\\\/add\\\\\" \\\\\"net group \\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\" * \\\\\\\\/ADD \\\\\\\\/DOMAIN\\\\\" \\\\\"certutil.exe *\\\\\\\\-urlcache* http*\\\\\" \\\\\"certutil.exe *\\\\\\\\-urlcache* ftp*\\\\\" \\\\\"netsh advfirewall firewall *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"attrib \\\\\\\\+S \\\\\\\\+H \\\\\\\\+R *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"schtasks* \\\\\\\\/create *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"schtasks* \\\\\\\\/sc minute*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Regasm.exe *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Regasm *\\\\\\\\\\\\\\\\AppData\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bitsadmin* \\\\\\\\/transfer*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe * \\\\\\\\-decode *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe * \\\\\\\\-decodehex *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\certutil.exe \\\\\\\\-ping *\\\\\" \\\\\"icacls * \\\\\\\\/grant Everyone\\\\\\\\:F \\\\\\\\/T \\\\\\\\/C \\\\\\\\/Q\\\\\" \\\\\"* wmic shadowcopy delete *\\\\\" \\\\\"* wbadmin.exe delete catalog \\\\\\\\-quiet*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.jse\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.js\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.vba\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wscript.exe *.vbe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.jse\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.js\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.vba\\\\\" \\\\\"*\\\\\\\\\\\\\\\\cscript.exe *.vbe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\fodhelper.exe\\\\\" \\\\\"*waitfor*\\\\\\\\/s*\\\\\" \\\\\"*waitfor*\\\\\\\\/si persist*\\\\\" \\\\\"*remote*\\\\\\\\/s*\\\\\" \\\\\"*remote*\\\\\\\\/c*\\\\\" \\\\\"*remote*\\\\\\\\/q*\\\\\" \\\\\"*AddInProcess*\\\\\" \\\\\"*msbuild*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Process-Start-Locations' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process run from unusual locations",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Process Start Locations",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\:\\\\\\\\\\\\\\\\RECYCLER\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\:\\\\\\\\\\\\\\\\SystemVolumeInformation\\\\\\\\*\\\\\" \\\\\"%windir%\\\\\\\\\\\\\\\\Tasks\\\\\\\\*\\\\\" \\\\\"%systemroot%\\\\\\\\\\\\\\\\debug\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Process-Start-Locations-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process run from unusual locations",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Process Start Locations",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\:\\\\\\\\\\\\\\\\RECYCLER\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\:\\\\\\\\\\\\\\\\SystemVolumeInformation\\\\\\\\*\\\\\" \\\\\"%windir%\\\\\\\\\\\\\\\\Tasks\\\\\\\\*\\\\\" \\\\\"%systemroot%\\\\\\\\\\\\\\\\debug\\\\\\\\*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:NetNTLM-Downgrade-Attack' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects post exploitation using NetNTLM downgrade attacks",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: NetNTLM Downgrade Attack",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"13\\\\\" AND registry_target_object:(\\\\\"*SYSTEM\\\\\\\\*ControlSet*\\\\\\\\\\\\\\\\Control\\\\\\\\\\\\\\\\Lsa\\\\\\\\\\\\\\\\lmcompatibilitylevel\\\\\" \\\\\"*SYSTEM\\\\\\\\*ControlSet*\\\\\\\\\\\\\\\\Control\\\\\\\\\\\\\\\\Lsa\\\\\\\\\\\\\\\\NtlmMinClientSec\\\\\" \\\\\"*SYSTEM\\\\\\\\*ControlSet*\\\\\\\\\\\\\\\\Control\\\\\\\\\\\\\\\\Lsa\\\\\\\\\\\\\\\\RestrictSendingNTLMTraffic\\\\\") AND registry_event_type:\\\\\"SetValue\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:NetNTLM-Downgrade-Attack-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects post exploitation using NetNTLM downgrade attacks",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: NetNTLM Downgrade Attack",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4657\\\\\" AND object_name:\\\\\"\\\\\\\\\\\\\\\\REGISTRY\\\\\\\\\\\\\\\\MACHINE\\\\\\\\\\\\\\\\SYSTEM\\\\\\\\*ControlSet*\\\\\\\\\\\\\\\\Control\\\\\\\\\\\\\\\\Lsa\\\\\" AND object_operation_type:\\\\\"Existing registry value modified\\\\\" AND object_value_name:(\\\\\"LmCompatibilityLevel\\\\\" \\\\\"NtlmMinClientSec\\\\\" \\\\\"RestrictSendingNTLMTraffic\\\\\")))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Commandline-Escape' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process that use escape characters",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Commandline Escape",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"\\\\\\\\^\\\\\" \\\\\"@\\\\\" \\\\\"\\\\\\\\-\\\\\" \\\\\"\\\\u2015\\\\\" \\\\\"c\\\\\\\\:\\\\\\\\/\\\\\" \\\\\"TAB\\\\\" \\\\\"\\\\\\\\^h\\\\\\\\^t\\\\\\\\^t\\\\\\\\^p\\\\\" \\\\\"h\\\\\\\\\\\\\"t\\\\\\\\\\\\\"t\\\\\\\\\\\\\"p\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Commandline-Escape-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process that use escape characters",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Commandline Escape",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"\\\\\\\\^\\\\\" \\\\\"@\\\\\" \\\\\"\\\\\\\\-\\\\\" \\\\\"\\\\u2015\\\\\" \\\\\"c\\\\\\\\:\\\\\\\\/\\\\\" \\\\\"TAB\\\\\" \\\\\"\\\\\\\\^h\\\\\\\\^t\\\\\\\\^t\\\\\\\\^p\\\\\" \\\\\"h\\\\\\\\\\\\\"t\\\\\\\\\\\\\"t\\\\\\\\\\\\\"p\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Password-Change-on-Directory-Service-Restore-Mode-DSRM-Account' <<EOF
{
  "type": "search",
  "search": {
    "description": "The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Password Change on Directory Service Restore Mode (DSRM) Account",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4794\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Backup-Catalog-Deleted' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects backup catalog deletions",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Backup Catalog Deleted",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__application__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"524\\\\\" AND source_name:\\\\\"Backup\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Weak-Encryption-Enabled-and-Kerberoast' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Weak Encryption Enabled and Kerberoast",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4738\\\\\") AND (\\\\\"DES\\\\\" OR \\\\\"Preauth\\\\\" OR \\\\\"Encrypted\\\\\") AND (\\\\\"Enabled\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Possible-Applocker-Bypass' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects execution of executables that can be used to bypass Applocker whitelisting",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Possible Applocker Bypass",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\msdt.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\installutil.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvcs.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regasm.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\msbuild.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\ieexec.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mshta.exe*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Possible-Applocker-Bypass-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects execution of executables that can be used to bypass Applocker whitelisting",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Possible Applocker Bypass",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\msdt.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\installutil.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvcs.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regasm.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\regsvr32.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\msbuild.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\ieexec.exe*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mshta.exe*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Possible-Remote-Password-Change-Through-SAMR' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). \"Audit User Account Management\" in \"Advanced Audit Policy Configuration\" has to be enabled in your local security policy / GPO to see this events.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Possible Remote Password Change Through SAMR",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"5145\\\\\" AND share_relative_target_name:\\\\\"samr\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:DNS-Server-Error-Failed-Loading-the-ServerLevelPluginDLL' <<EOF
{
  "type": "search",
  "search": {
    "description": "This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: DNS Server Error Failed Loading the ServerLevelPluginDLL",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"150\\\\\" \\\\\"770\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Rare-Service-Installs' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Rare Service Installs",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"7045\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:User-Added-to-Local-Administrators' <<EOF
{
  "type": "search",
  "search": {
    "description": "This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: User Added to Local Administrators",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4732\\\\\" AND group_name:\\\\\"Administrators\\\\\") AND NOT (user_name:\\\\\"*$\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Mimikatz-Use' <<EOF
{
  "type": "search",
  "search": {
    "description": "This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Mimikatz Use",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(\\\\\"mimikatz\\\\\" OR \\\\\"mimilib\\\\\" OR \\\\\"3 eo.oe\\\\\" OR \\\\\"eo.oe.kiwi\\\\\" OR \\\\\"privilege\\\\\\\\:\\\\\\\\:debug\\\\\" OR \\\\\"sekurlsa\\\\\\\\:\\\\\\\\:logonpasswords\\\\\" OR \\\\\"lsadump\\\\\\\\:\\\\\\\\:sam\\\\\" OR \\\\\"mimidrv.sys\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:IIS-Native-Code-Module-Command-Line-Installation' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious IIS native-code module installations via command line",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: IIS Native-Code Module Command Line Installation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\APPCMD.EXE install module \\\\\\\\/name\\\\\\\\:*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:IIS-Native-Code-Module-Command-Line-Installation-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious IIS native-code module installations via command line",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: IIS Native-Code Module Command Line Installation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\APPCMD.EXE install module \\\\\\\\/name\\\\\\\\:*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Eventlog-Cleared' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a cleared Windows Eventlog as e.g. caused by \"wevtutil cl\" command execution",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Eventlog Cleared",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"104\\\\\" AND source_name:\\\\\"Eventlog\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Microsoft-Malware-Protection-Engine-Crash' <<EOF
{
  "type": "search",
  "search": {
    "description": "This rule detects a suspicious crash of the Microsoft Malware Protection Engine",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Microsoft Malware Protection Engine Crash",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__application__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1000\\\\\" AND source_name:\\\\\"Application Error\\\\\") OR (event_id:\\\\\"1001\\\\\" AND source_name:\\\\\"Windows Error Reporting\\\\\")) AND (\\\\\"MsMpEng.exe\\\\\" AND \\\\\"mpengine.dll\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Invocation-of-Active-Directory-Diagnostic-Tool-ntdsutil.exe' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\ntdsutil.exe *\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Invocation-of-Active-Directory-Diagnostic-Tool-ntdsutil.exe-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\ntdsutil.exe *\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Kerberos-RC4-Ticket-Encryption' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects service ticket requests using RC4 encryption type",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Kerberos RC4 Ticket Encryption",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4769\\\\\" AND ticket_options:\\\\\"0x40810000\\\\\" AND ticket_encryption_type:\\\\\"0x17\\\\\") AND NOT (service_name:\\\\\"$*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Executable-used-by-PlugX-in-Uncommon-Location-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Executable used by PlugX in Uncommon Location",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\CamMute.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Lenovo\\\\\\\\\\\\\\\\Communication Utility\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\chrome_frame_helper.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Google\\\\\\\\\\\\\\\\Chrome\\\\\\\\\\\\\\\\application\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\dvcemumanager.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Microsoft Device Emulator\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Gadget.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Windows Media Player\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\hcc.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\HTML Help Workshop\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\hkcmd.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\System32\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SysNative\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SysWowo64\\\\\\\\*\\\\\"))) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Mc.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Visual Studio*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft SDK*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Kit*\\\\\"))) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\MsMpEng.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Security Client\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Defender\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\AntiMalware\\\\\\\\*\\\\\"))) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\msseces.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Microsoft Security Center\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\OInfoP11.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\Common Files\\\\\\\\\\\\\\\\Microsoft Shared\\\\\\\\*\\\\\")) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\OleView.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Visual Studio*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft SDK*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Kit*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Resource Kit\\\\\\\\*\\\\\"))) OR ((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\OleView.exe\\\\\") AND NOT (event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\Microsoft Visual Studio*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft SDK*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Kit*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Windows Resource Kit\\\\\\\\*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\*\\\\\")))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Pass-the-Hash-Activity' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the attack technique pass the hash which is used to move laterally inside the network",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Pass the Hash Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(logon_type:\\\\\"3\\\\\" AND host_name:\\\\\"%Workstations%\\\\\" AND event_id:\\\\\"4624\\\\\" AND logon_process_name:\\\\\"NtLmSsp\\\\\" AND src_host:\\\\\"%Workstations%\\\\\" OR logon_type:\\\\\"3\\\\\" AND host_name:\\\\\"%Workstations%\\\\\" AND event_id:\\\\\"4625\\\\\" AND logon_process_name:\\\\\"NtLmSsp\\\\\" AND src_host:\\\\\"%Workstations%\\\\\") AND NOT (service_account_name:\\\\\"ANONYMOUS LOGON\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Password-Dumper-Activity-on-LSASS' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Password Dumper Activity on LSASS",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4656\\\\\" AND object_access_mask_requested:\\\\\"0x705\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\lsass.exe\\\\\" AND object_type:\\\\\"SAM_DOMAIN\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Rare-Schtasks-Creations' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Rare Schtasks Creations",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4698\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Eventlog-Cleared-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "One of the Windows Eventlogs has been cleared",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Eventlog Cleared",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"104\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Kerberos-Manipulation' <<EOF
{
  "type": "search",
  "search": {
    "description": "This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Kerberos Manipulation",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(ticket_failure_code:(\\\\\"0x9\\\\\" \\\\\"0xA\\\\\" \\\\\"0xB\\\\\" \\\\\"0xF\\\\\" \\\\\"0x10\\\\\" \\\\\"0x11\\\\\" \\\\\"0x13\\\\\" \\\\\"0x14\\\\\" \\\\\"0x1A\\\\\" \\\\\"0x1F\\\\\" \\\\\"0x21\\\\\" \\\\\"0x22\\\\\" \\\\\"0x23\\\\\" \\\\\"0x24\\\\\" \\\\\"0x26\\\\\" \\\\\"0x27\\\\\" \\\\\"0x28\\\\\" \\\\\"0x29\\\\\" \\\\\"0x2C\\\\\" \\\\\"0x2D\\\\\" \\\\\"0x2E\\\\\" \\\\\"0x2F\\\\\" \\\\\"0x31\\\\\" \\\\\"0x32\\\\\" \\\\\"0x3E\\\\\" \\\\\"0x3F\\\\\" \\\\\"0x40\\\\\" \\\\\"0x41\\\\\" \\\\\"0x43\\\\\" \\\\\"0x44\\\\\") AND event_id:(\\\\\"675\\\\\" \\\\\"4768\\\\\" \\\\\"4769\\\\\" \\\\\"4771\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WCE-wceaux.dll-Access' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WCE wceaux.dll Access",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"4656\\\\\" \\\\\"4658\\\\\" \\\\\"4660\\\\\" \\\\\"4663\\\\\") AND object_name:\\\\\"*\\\\\\\\\\\\\\\\wceaux.dll\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Phantom-DLLs-Usage' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Phantom DLLs usage and matching executable",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Phantom DLLs Usage",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*ntbackup*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\edbbcli.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\esebcli2.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bcrypt.dll*\\\\\" \\\\\"*sessmgr*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SalemHook.dll*\\\\\" \\\\\"*certreq*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\msfte.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mstracer.dll*\\\\\" \\\\\"*fxscover*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\TPPrnUIENU.dll*\\\\\" \\\\\"*dxdiag*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\DXGIDebug.dll*\\\\\" \\\\\"*msinfo32*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\fveapi.dll*\\\\\" \\\\\"*narrator*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\MSTTSLocEnUS.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Wow64Log.dll*\\\\\" \\\\\"*Dism*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Dism\\\\\\\\\\\\\\\\wimgapi.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\DismCore.dll*\\\\\" \\\\\"*FileHistory*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\api\\\\\\\\-ms\\\\\\\\-win\\\\\\\\-core\\\\\\\\-winrt\\\\\\\\-l1\\\\\\\\-1\\\\\\\\-0.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\mscoree.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\ole32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\urlmon.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_32\\\\\\\\\\\\\\\\mscorlib\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\oleaut32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_32\\\\\\\\\\\\\\\\mscorlib\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\shell32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_MSIL\\\\\\\\\\\\\\\\MIGUIControls\\\\\\\\\\\\\\\\v4.0_1.0.0.0__31bf3856ad364e35\\\\\\\\\\\\\\\\ntdll.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_MSIL\\\\\\\\\\\\\\\\System.Windows.Forms\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\comctl32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_MSIL\\\\\\\\\\\\\\\\System.Windows.Forms\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\uxtheme.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\api\\\\\\\\-ms\\\\\\\\-win\\\\\\\\-core\\\\\\\\-winrt\\\\\\\\-l1\\\\\\\\-1\\\\\\\\-0.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\mscoree.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\ole32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\VERSION.dll*\\\\\" \\\\\"*Narrator*\\\\\" \\\\\"*speech\\\\\\\\\\\\\\\\engines\\\\\\\\\\\\\\\\tts\\\\\\\\\\\\\\\\MSTTSLocEnUS.DLL\\\\\" \\\\\"*omadmclient*\\\\\" \\\\\"*cmnet.dll*\\\\\" \\\\\"*PresentationHost*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\WPF\\\\\\\\\\\\\\\\PresentationHost_v0400.dll*\\\\\" \\\\\"*provtool*\\\\\" \\\\\"*MvHelper.dll*\\\\\" \\\\\"*SearchIndexer*\\\\\" \\\\\"*msfte.dll*\\\\\" \\\\\"*msTracer.dll*\\\\\" \\\\\"*SearchProtocolHost*\\\\\" \\\\\"*msfte.dll*\\\\\" \\\\\"*msTracer.dll*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Phantom-DLLs-Usage-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Phantom DLLs usage and matching executable",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Phantom DLLs Usage",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*ntbackup*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\edbbcli.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\esebcli2.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\bcrypt.dll*\\\\\" \\\\\"*sessmgr*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\SalemHook.dll*\\\\\" \\\\\"*certreq*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\msfte.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mstracer.dll*\\\\\" \\\\\"*fxscover*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\TPPrnUIENU.dll*\\\\\" \\\\\"*dxdiag*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\DXGIDebug.dll*\\\\\" \\\\\"*msinfo32*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\fveapi.dll*\\\\\" \\\\\"*narrator*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\MSTTSLocEnUS.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Wow64Log.dll*\\\\\" \\\\\"*Dism*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Dism\\\\\\\\\\\\\\\\wimgapi.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\DismCore.dll*\\\\\" \\\\\"*FileHistory*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\api\\\\\\\\-ms\\\\\\\\-win\\\\\\\\-core\\\\\\\\-winrt\\\\\\\\-l1\\\\\\\\-1\\\\\\\\-0.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\mscoree.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\ole32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\urlmon.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_32\\\\\\\\\\\\\\\\mscorlib\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\oleaut32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_32\\\\\\\\\\\\\\\\mscorlib\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\shell32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_MSIL\\\\\\\\\\\\\\\\MIGUIControls\\\\\\\\\\\\\\\\v4.0_1.0.0.0__31bf3856ad364e35\\\\\\\\\\\\\\\\ntdll.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_MSIL\\\\\\\\\\\\\\\\System.Windows.Forms\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\comctl32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.Net\\\\\\\\\\\\\\\\assembly\\\\\\\\\\\\\\\\GAC_MSIL\\\\\\\\\\\\\\\\System.Windows.Forms\\\\\\\\\\\\\\\\v4.0_4.0.0.0__b77a5c561934e089\\\\\\\\\\\\\\\\uxtheme.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\api\\\\\\\\-ms\\\\\\\\-win\\\\\\\\-core\\\\\\\\-winrt\\\\\\\\-l1\\\\\\\\-1\\\\\\\\-0.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\mscoree.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\ole32.dll*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\VERSION.dll*\\\\\" \\\\\"*Narrator*\\\\\" \\\\\"*speech\\\\\\\\\\\\\\\\engines\\\\\\\\\\\\\\\\tts\\\\\\\\\\\\\\\\MSTTSLocEnUS.DLL\\\\\" \\\\\"*omadmclient*\\\\\" \\\\\"*cmnet.dll*\\\\\" \\\\\"*PresentationHost*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Microsoft.NET\\\\\\\\\\\\\\\\Framework\\\\\\\\\\\\\\\\v4.0.30319\\\\\\\\\\\\\\\\WPF\\\\\\\\\\\\\\\\PresentationHost_v0400.dll*\\\\\" \\\\\"*provtool*\\\\\" \\\\\"*MvHelper.dll*\\\\\" \\\\\"*SearchIndexer*\\\\\" \\\\\"*msfte.dll*\\\\\" \\\\\"*msTracer.dll*\\\\\" \\\\\"*SearchProtocolHost*\\\\\" \\\\\"*msfte.dll*\\\\\" \\\\\"*msTracer.dll*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:USB-Device-Plugged' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects plugged USB devices",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: USB Device Plugged",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"2003\\\\\" \\\\\"2100\\\\\" \\\\\"2102\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PsExec-Service-Start' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects a PsExec service start",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: PsExec Service Start",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4688\\\\\" AND command_line:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\PSEXESVC.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Relevant-Anti-Virus-Event' <<EOF
{
  "type": "search",
  "search": {
    "description": "This detection method points out highly relevant Antivirus events",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Relevant Anti-Virus Event",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__application__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(\\\\\"HTool\\\\\" OR \\\\\"Hacktool\\\\\" OR \\\\\"ASP\\\\\\\\/Backdoor\\\\\" OR \\\\\"JSP\\\\\\\\/Backdoor\\\\\" OR \\\\\"PHP\\\\\\\\/Backdoor\\\\\" OR \\\\\"Backdoor.ASP\\\\\" OR \\\\\"Backdoor.JSP\\\\\" OR \\\\\"Backdoor.PHP\\\\\" OR \\\\\"Webshell\\\\\" OR \\\\\"Portscan\\\\\" OR \\\\\"Mimikatz\\\\\" OR \\\\\"WinCred\\\\\" OR \\\\\"PlugX\\\\\" OR \\\\\"Korplug\\\\\" OR \\\\\"Pwdump\\\\\" OR \\\\\"Chopper\\\\\" OR \\\\\"WmiExec\\\\\" OR \\\\\"Xscan\\\\\" OR \\\\\"Clearlog\\\\\" OR \\\\\"ASPXSpy\\\\\") AND NOT (\\\\\"Keygen\\\\\" OR \\\\\"Crack\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Secure-Deletion-with-SDelete' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects renaming of file while deletion with SDelete tool",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Secure Deletion with SDelete",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"4656\\\\\" \\\\\"4663\\\\\" \\\\\"4658\\\\\") AND object_name:(\\\\\"*.AAA\\\\\" \\\\\"*.ZZZ\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Interactive-Logon-to-Server-Systems' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects interactive console logons to",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Interactive Logon to Server Systems",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(logon_type:\\\\\"2\\\\\" AND host_name:(\\\\\"%ServerSystems%\\\\\" \\\\\"%DomainControllers%\\\\\") AND event_id:(\\\\\"528\\\\\" \\\\\"529\\\\\" \\\\\"4624\\\\\" \\\\\"4625\\\\\")) AND NOT (host_name:\\\\\"%Workstations%\\\\\" AND logon_process_name:\\\\\"Advapi\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Admin-User-Remote-Logon' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detect remote login by Administrator user depending on internal pattern",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Admin User Remote Logon",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(logon_type:\\\\\"10\\\\\" AND logon_authentication_package:\\\\\"Negotiate\\\\\" AND event_id:\\\\\"4624\\\\\" AND service_account_name:\\\\\"Admin\\\\\\\\-*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Security-Eventlog-Cleared' <<EOF
{
  "type": "search",
  "search": {
    "description": "Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Security Eventlog Cleared",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"517\\\\\" \\\\\"1102\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:MsiExec-Web-Install' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious msiexec proess starts with web addreses as parameter",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: MsiExec Web Install",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"* msiexec*\\\\\\\\:\\\\\\\\\\\\\\\\\\\\\\\\/\\\\\\\\\\\\\\\\\\\\\\\\/*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:MsiExec-Web-Install-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious msiexec proess starts with web addreses as parameter",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: MsiExec Web Install",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"* msiexec*\\\\\\\\:\\\\\\\\\\\\\\\\\\\\\\\\/\\\\\\\\\\\\\\\\\\\\\\\\/*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Addition-of-SID-History-to-Active-Directory-Object' <<EOF
{
  "type": "search",
  "search": {
    "description": "An attacker can use the SID history attribute to gain additional privileges.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Addition of SID History to Active Directory Object",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"4765\\\\\" \\\\\"4766\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Active-Directory-User-Backdoors' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects scenarios where one can control another users account without having to use their credentials via msDS-AllowedToDelegateTo and or service principal names (SPN).",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Active Directory User Backdoors",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4738\\\\\" AND user_attribute_allowed_todelegate:\\\\\"*\\\\\") OR (dsobject_class:\\\\\"user\\\\\" AND dsobject_attribute_name:\\\\\"servicePrincipalName\\\\\" AND event_id:\\\\\"5136\\\\\") OR (dsobject_attribute_name:\\\\\"msDS\\\\\\\\-AllowedToDelegateTo\\\\\" AND event_id:\\\\\"5136\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Rundll32-Activity' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process related to rundll32 based on arguments",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Rundll32 Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* url.dll,*OpenURL *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* url.dll,*OpenURLA *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* url.dll,*FileProtocolHandler *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* zipfldr.dll,*RouteTheCall *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* Shell32.dll,*Control_RunDLL *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe javascript\\\\\\\\:*\\\\\" \\\\\"* url.dll,*OpenURL *\\\\\" \\\\\"* url.dll,*OpenURLA *\\\\\" \\\\\"* url.dll,*FileProtocolHandler *\\\\\" \\\\\"* zipfldr.dll,*RouteTheCall *\\\\\" \\\\\"* Shell32.dll,*Control_RunDLL *\\\\\" \\\\\"* javascript\\\\\\\\:*\\\\\" \\\\\"*.RegisterXLL*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-Rundll32-Activity-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process related to rundll32 based on arguments",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious Rundll32 Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* url.dll,*OpenURL *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* url.dll,*OpenURLA *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* url.dll,*FileProtocolHandler *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* zipfldr.dll,*RouteTheCall *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe* Shell32.dll,*Control_RunDLL *\\\\\" \\\\\"*\\\\\\\\\\\\\\\\rundll32.exe javascript\\\\\\\\:*\\\\\" \\\\\"* url.dll,*OpenURL *\\\\\" \\\\\"* url.dll,*OpenURLA *\\\\\" \\\\\"* url.dll,*FileProtocolHandler *\\\\\" \\\\\"* zipfldr.dll,*RouteTheCall *\\\\\" \\\\\"* Shell32.dll,*Control_RunDLL *\\\\\" \\\\\"* javascript\\\\\\\\:*\\\\\" \\\\\"*.RegisterXLL*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Hacktool-Use' <<EOF
{
  "type": "search",
  "search": {
    "description": "This method detects well-known keywords, certain field combination that appear in Windows Eventlog when certain hack tools are used",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Hacktool Use",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"4776\\\\\" \\\\\"4624\\\\\" \\\\\"4625\\\\\") AND src_host:\\\\\"RULER\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:DHCP-Server-Error-Failed-Loading-the-CallOut-DLL' <<EOF
{
  "type": "search",
  "search": {
    "description": "This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: DHCP Server Error Failed Loading the CallOut DLL",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__system__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"1031\\\\\" \\\\\"1032\\\\\" \\\\\"1034\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-RASdial-Activity' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process related to rasdial.exe",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious RASdial Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"rasdial\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-RASdial-Activity-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious process related to rasdial.exe",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious RASdial Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"rasdial\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Account-Tampering---Suspicious-Failed-Logon-Reasons' <<EOF
{
  "type": "search",
  "search": {
    "description": "This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Account Tampering - Suspicious Failed Logon Reasons",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:(\\\\\"4625\\\\\" \\\\\"4776\\\\\") AND logon_failure_status:(\\\\\"3221225586\\\\\" \\\\\"3221225583\\\\\" \\\\\"3221225584\\\\\" \\\\\"3221226515\\\\\" \\\\\"3221225868\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WMI-Persistence---Script-Event-Consumer' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WMI script event consumers",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WMI Persistence - Script Event Consumer",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_parent_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\svchost.exe\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\WINDOWS\\\\\\\\\\\\\\\\system32\\\\\\\\\\\\\\\\wbem\\\\\\\\\\\\\\\\scrcons.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WMI-Persistence---Script-Event-Consumer-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WMI script event consumers",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WMI Persistence - Script Event Consumer",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND process_parent_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\System32\\\\\\\\\\\\\\\\svchost.exe\\\\\" AND process_path:\\\\\"C\\\\\\\\:\\\\\\\\\\\\\\\\WINDOWS\\\\\\\\\\\\\\\\system32\\\\\\\\\\\\\\\\wbem\\\\\\\\\\\\\\\\scrcons.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-PowerShell-Invocations---Generic' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious PowerShell invocation command parameters",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious PowerShell Invocations - Generic",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((\\\\\" \\\\\\\\-noni \\\\\" OR \\\\\" \\\\\\\\-noninteractive \\\\\") AND (\\\\\" \\\\\\\\-w hidden \\\\\" OR \\\\\" \\\\\\\\-window hidden \\\\\" OR \\\\\" \\\\\\\\- windowstyle hidden \\\\\") AND (\\\\\" \\\\\\\\-enc \\\\\" OR \\\\\" \\\\\\\\-EncodedCommand \\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PowerShell-called-from-an-Executable-Version-Mismatch' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects PowerShell called from an executable by the version mismatch method",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: PowerShell called from an Executable Version Mismatch",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(powershell.host.version:\\\\\"3.*\\\\\" AND event_id:\\\\\"400\\\\\" AND powershell.engine.version:(\\\\\"2.*\\\\\" \\\\\"4.*\\\\\" \\\\\"5.*\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PowerShell-Downgrade-Attack' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: PowerShell Downgrade Attack",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"400\\\\\" AND powershell.engine.version:\\\\\"2.*\\\\\") AND NOT (powershell.host.version:\\\\\"2.*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Malicious-PowerShell-Commandlets' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Commandlet names from well-known PowerShell exploitation frameworks",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Malicious PowerShell Commandlets",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(\\\\\"Invoke\\\\\\\\-DllInjection\\\\\" OR \\\\\"Invoke\\\\\\\\-Shellcode\\\\\" OR \\\\\"Invoke\\\\\\\\-WmiCommand\\\\\" OR \\\\\"Get\\\\\\\\-GPPPassword\\\\\" OR \\\\\"Get\\\\\\\\-Keystrokes\\\\\" OR \\\\\"Get\\\\\\\\-TimedScreenshot\\\\\" OR \\\\\"Get\\\\\\\\-VaultCredential\\\\\" OR \\\\\"Invoke\\\\\\\\-CredentialInjection\\\\\" OR \\\\\"Invoke\\\\\\\\-Mimikatz\\\\\" OR \\\\\"Invoke\\\\\\\\-NinjaCopy\\\\\" OR \\\\\"Invoke\\\\\\\\-TokenManipulation\\\\\" OR \\\\\"Out\\\\\\\\-Minidump\\\\\" OR \\\\\"VolumeShadowCopyTools\\\\\" OR \\\\\"Invoke\\\\\\\\-ReflectivePEInjection\\\\\" OR \\\\\"Invoke\\\\\\\\-UserHunter\\\\\" OR \\\\\"Find\\\\\\\\-GPOLocation\\\\\" OR \\\\\"Invoke\\\\\\\\-ACLScanner\\\\\" OR \\\\\"Invoke\\\\\\\\-DowngradeAccount\\\\\" OR \\\\\"Get\\\\\\\\-ServiceUnquoted\\\\\" OR \\\\\"Get\\\\\\\\-ServiceFilePermission\\\\\" OR \\\\\"Get\\\\\\\\-ServicePermission\\\\\" OR \\\\\"Invoke\\\\\\\\-ServiceAbuse\\\\\" OR \\\\\"Install\\\\\\\\-ServiceBinary\\\\\" OR \\\\\"Get\\\\\\\\-RegAutoLogon\\\\\" OR \\\\\"Get\\\\\\\\-VulnAutoRun\\\\\" OR \\\\\"Get\\\\\\\\-VulnSchTask\\\\\" OR \\\\\"Get\\\\\\\\-UnattendedInstallFile\\\\\" OR \\\\\"Get\\\\\\\\-WebConfig\\\\\" OR \\\\\"Get\\\\\\\\-ApplicationHost\\\\\" OR \\\\\"Get\\\\\\\\-RegAlwaysInstallElevated\\\\\" OR \\\\\"Get\\\\\\\\-Unconstrained\\\\\" OR \\\\\"Add\\\\\\\\-RegBackdoor\\\\\" OR \\\\\"Add\\\\\\\\-ScrnSaveBackdoor\\\\\" OR \\\\\"Gupt\\\\\\\\-Backdoor\\\\\" OR \\\\\"Invoke\\\\\\\\-ADSBackdoor\\\\\" OR \\\\\"Enabled\\\\\\\\-DuplicateToken\\\\\" OR \\\\\"Invoke\\\\\\\\-PsUaCme\\\\\" OR \\\\\"Remove\\\\\\\\-Update\\\\\" OR \\\\\"Check\\\\\\\\-VM\\\\\" OR \\\\\"Get\\\\\\\\-LSASecret\\\\\" OR \\\\\"Get\\\\\\\\-PassHashes\\\\\" OR \\\\\"Invoke\\\\\\\\-Mimikatz\\\\\" OR \\\\\"Show\\\\\\\\-TargetScreen\\\\\" OR \\\\\"Port\\\\\\\\-Scan\\\\\" OR \\\\\"Invoke\\\\\\\\-PoshRatHttp\\\\\" OR \\\\\"Invoke\\\\\\\\-PowerShellTCP\\\\\" OR \\\\\"Invoke\\\\\\\\-PowerShellWMI\\\\\" OR \\\\\"Add\\\\\\\\-Exfiltration\\\\\" OR \\\\\"Add\\\\\\\\-Persistence\\\\\" OR \\\\\"Do\\\\\\\\-Exfiltration\\\\\" OR \\\\\"Start\\\\\\\\-CaptureServer\\\\\" OR \\\\\"Invoke\\\\\\\\-DllInjection\\\\\" OR \\\\\"Invoke\\\\\\\\-ReflectivePEInjection\\\\\" OR \\\\\"Invoke\\\\\\\\-ShellCode\\\\\" OR \\\\\"Get\\\\\\\\-ChromeDump\\\\\" OR \\\\\"Get\\\\\\\\-ClipboardContents\\\\\" OR \\\\\"Get\\\\\\\\-FoxDump\\\\\" OR \\\\\"Get\\\\\\\\-IndexedItem\\\\\" OR \\\\\"Get\\\\\\\\-Keystrokes\\\\\" OR \\\\\"Get\\\\\\\\-Screenshot\\\\\" OR \\\\\"Invoke\\\\\\\\-Inveigh\\\\\" OR \\\\\"Invoke\\\\\\\\-NetRipper\\\\\" OR \\\\\"Invoke\\\\\\\\-NinjaCopy\\\\\" OR \\\\\"Out\\\\\\\\-Minidump\\\\\" OR \\\\\"Invoke\\\\\\\\-EgressCheck\\\\\" OR \\\\\"Invoke\\\\\\\\-PostExfil\\\\\" OR \\\\\"Invoke\\\\\\\\-PSInject\\\\\" OR \\\\\"Invoke\\\\\\\\-RunAs\\\\\" OR \\\\\"MailRaider\\\\\" OR \\\\\"New\\\\\\\\-HoneyHash\\\\\" OR \\\\\"Set\\\\\\\\-MacAttribute\\\\\" OR \\\\\"Get\\\\\\\\-VaultCredential\\\\\" OR \\\\\"Invoke\\\\\\\\-DCSync\\\\\" OR \\\\\"Invoke\\\\\\\\-Mimikatz\\\\\" OR \\\\\"Invoke\\\\\\\\-PowerDump\\\\\" OR \\\\\"Invoke\\\\\\\\-TokenManipulation\\\\\" OR \\\\\"Exploit\\\\\\\\-Jboss\\\\\" OR \\\\\"Invoke\\\\\\\\-ThunderStruck\\\\\" OR \\\\\"Invoke\\\\\\\\-VoiceTroll\\\\\" OR \\\\\"Set\\\\\\\\-Wallpaper\\\\\" OR \\\\\"Invoke\\\\\\\\-InveighRelay\\\\\" OR \\\\\"Invoke\\\\\\\\-PsExec\\\\\" OR \\\\\"Invoke\\\\\\\\-SSHCommand\\\\\" OR \\\\\"Get\\\\\\\\-SecurityPackages\\\\\" OR \\\\\"Install\\\\\\\\-SSP\\\\\" OR \\\\\"Invoke\\\\\\\\-BackdoorLNK\\\\\" OR \\\\\"PowerBreach\\\\\" OR \\\\\"Get\\\\\\\\-GPPPassword\\\\\" OR \\\\\"Get\\\\\\\\-SiteListPassword\\\\\" OR \\\\\"Get\\\\\\\\-System\\\\\" OR \\\\\"Invoke\\\\\\\\-BypassUAC\\\\\" OR \\\\\"Invoke\\\\\\\\-Tater\\\\\" OR \\\\\"Invoke\\\\\\\\-WScriptBypassUAC\\\\\" OR \\\\\"PowerUp\\\\\" OR \\\\\"PowerView\\\\\" OR \\\\\"Get\\\\\\\\-RickAstley\\\\\" OR \\\\\"Find\\\\\\\\-Fruit\\\\\" OR \\\\\"HTTP\\\\\\\\-Login\\\\\" OR \\\\\"Find\\\\\\\\-TrustedDocuments\\\\\" OR \\\\\"Invoke\\\\\\\\-Paranoia\\\\\" OR \\\\\"Invoke\\\\\\\\-WinEnum\\\\\" OR \\\\\"Invoke\\\\\\\\-ARPScan\\\\\" OR \\\\\"Invoke\\\\\\\\-PortScan\\\\\" OR \\\\\"Invoke\\\\\\\\-ReverseDNSLookup\\\\\" OR \\\\\"Invoke\\\\\\\\-SMBScanner\\\\\" OR \\\\\"Invoke\\\\\\\\-Mimikittenz\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-PowerShell-Download' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious PowerShell download command",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious PowerShell Download",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(\\\\\"System.Net.WebClient\\\\\\\\).DownloadString\\\\\\\\(\\\\\" OR \\\\\"system.net.webclient\\\\\\\\).downloadfile\\\\\\\\(\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PowerShell-Credential-Prompt' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects PowerShell calling a credential prompt",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: PowerShell Credential Prompt",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4104\\\\\") AND (\\\\\"PromptForCredential\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Suspicious-PowerShell-Invocations---Specific' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious PowerShell invocation command parameters",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Suspicious PowerShell Invocations - Specific",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(\\\\\" \\\\\\\\-nop \\\\\\\\-w hidden \\\\\\\\-c * \\\\\\\\[Convert\\\\\\\\]\\\\\\\\:\\\\\\\\:FromBase64String\\\\\" OR \\\\\" \\\\\\\\-w hidden \\\\\\\\-noni \\\\\\\\-nop \\\\\\\\-c \\\\\\\\\\\\\"iex\\\\\\\\(New\\\\\\\\-Object\\\\\" OR \\\\\" \\\\\\\\-w hidden \\\\\\\\-ep bypass \\\\\\\\-Enc\\\\\" OR \\\\\"powershell.exe reg add HKCU\\\\\\\\\\\\\\\\software\\\\\\\\\\\\\\\\microsoft\\\\\\\\\\\\\\\\windows\\\\\\\\\\\\\\\\currentversion\\\\\\\\\\\\\\\\run\\\\\" OR \\\\\"bypass \\\\\\\\-noprofile \\\\\\\\-windowstyle hidden \\\\\\\\(new\\\\\\\\-object system.net.webclient\\\\\\\\).download\\\\\" OR \\\\\"iex\\\\\\\\(New\\\\\\\\-Object Net.WebClient\\\\\\\\).Download\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Malicious-PowerShell-Commandlets-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects Commandlet names from well-known PowerShell exploitation frameworks",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Malicious PowerShell Commandlets",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(\\\\\"AdjustTokenPrivileges\\\\\" OR \\\\\"IMAGE_NT_OPTIONAL_HDR64_MAGIC\\\\\" OR \\\\\"Management.Automation.RuntimeException\\\\\" OR \\\\\"Microsoft.Win32.UnsafeNativeMethods\\\\\" OR \\\\\"ReadProcessMemory.Invoke\\\\\" OR \\\\\"Runtime.InteropServices\\\\\" OR \\\\\"SE_PRIVILEGE_ENABLED\\\\\" OR \\\\\"System.Security.Cryptography\\\\\" OR \\\\\"System.Runtime.InteropServices\\\\\" OR \\\\\"LSA_UNICODE_STRING\\\\\" OR \\\\\"MiniDumpWriteDump\\\\\" OR \\\\\"PAGE_EXECUTE_READ\\\\\" OR \\\\\"Net.Sockets.SocketFlags\\\\\" OR \\\\\"Reflection.Assembly\\\\\" OR \\\\\"SECURITY_DELEGATION\\\\\" OR \\\\\"TOKEN_ADJUST_PRIVILEGES\\\\\" OR \\\\\"TOKEN_ALL_ACCESS\\\\\" OR \\\\\"TOKEN_ASSIGN_PRIMARY\\\\\" OR \\\\\"TOKEN_DUPLICATE\\\\\" OR \\\\\"TOKEN_ELEVATION\\\\\" OR \\\\\"TOKEN_IMPERSONATE\\\\\" OR \\\\\"TOKEN_INFORMATION_CLASS\\\\\" OR \\\\\"TOKEN_PRIVILEGES\\\\\" OR \\\\\"TOKEN_QUERY\\\\\" OR \\\\\"Metasploit\\\\\" OR \\\\\"Mimikatz\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PowerShell-PSAttack' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects the use of PSAttack PowerShell hack tool",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: PowerShell PSAttack",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__powershell__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4103\\\\\") AND (\\\\\"PS ATTACK\\\\\\\\!\\\\\\\\!\\\\\\\\!\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Rare-Scheduled-Task-Creations' <<EOF
{
  "type": "search",
  "search": {
    "description": "This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Rare Scheduled Task Creations",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"106\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:PsExec-Tool-Execution' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects PsExec service installation and execution events (service and Sysmon)",
    "version": 1,
    "columns": [
      "event_id",
      "command_line",
      "ParentCommandLine",
      "service_name",
      "service_image_path"
    ],
    "hits": 0,
    "title": "Sigma: PsExec Tool Execution",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"7036\\\\\" AND service_name:\\\\\"PSEXESVC\\\\\") OR (event_id:\\\\\"7045\\\\\" AND service_name:\\\\\"PSEXESVC\\\\\" AND service_image_path:\\\\\"*\\\\\\\\\\\\\\\\PSEXESVC.exe\\\\\") OR (user:\\\\\"NT AUTHORITY\\\\\\\\\\\\\\\\SYSTEM\\\\\" AND event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\PSEXESVC.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WMI-Persistence' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WMI Persistence",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__wmiactivity__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"5861\\\\\") AND (\\\\\"ActiveScriptEventConsumer\\\\\" OR \\\\\"CommandLineEventConsumer\\\\\" OR \\\\\"CommandLineTemplate\\\\\" OR \\\\\"Binding EventFilter\\\\\") OR (event_id:\\\\\"5859\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Adwind-RAT-/-JRAT' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Adwind RAT / JRAT",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Roaming\\\\\\\\\\\\\\\\Oracle*\\\\\\\\\\\\\\\\java*.exe *\\\\\" \\\\\"*cscript.exe *Retrive*.vbs *\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Adwind-RAT-/-JRAT-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Adwind RAT / JRAT",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Roaming\\\\\\\\\\\\\\\\Oracle\\\\\\\\\\\\\\\\bin\\\\\\\\\\\\\\\\java*.exe\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Adwind-RAT-/-JRAT-3' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Adwind RAT / JRAT",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"11\\\\\" AND file_name:(\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Roaming\\\\\\\\\\\\\\\\Oracle\\\\\\\\\\\\\\\\bin\\\\\\\\\\\\\\\\java*.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\Retrive*.vbs\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:Adwind-RAT-/-JRAT-4' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects javaw.exe in AppData folder as used by Adwind / JRAT",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: Adwind RAT / JRAT",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"(event_id:\\\\\"13\\\\\" AND registry_details:\\\\\"%AppData%\\\\\\\\\\\\\\\\Oracle\\\\\\\\\\\\\\\\bin\\\\\\\\*\\\\\" AND registry_target_object:\\\\\"\\\\\\\\\\\\\\\\REGISTRY\\\\\\\\\\\\\\\\MACHINE\\\\\\\\\\\\\\\\SOFTWARE\\\\\\\\\\\\\\\\Microsoft\\\\\\\\\\\\\\\\Windows\\\\\\\\\\\\\\\\CurrentVersion\\\\\\\\\\\\\\\\Run*\\\\\")\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WannaCry-Ransomware' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WannaCry Ransomware Activity",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WannaCry Ransomware",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__security__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"4688\\\\\" AND command_line:(\\\\\"*vssadmin delete shadows*\\\\\" \\\\\"*icacls * \\\\\\\\/grant Everyone\\\\\\\\:F \\\\\\\\/T \\\\\\\\/C \\\\\\\\/Q*\\\\\" \\\\\"*bcdedit \\\\\\\\/set \\\\\\\\{default\\\\\\\\} recoveryenabled no*\\\\\" \\\\\"*wbadmin delete catalog \\\\\\\\-quiet*\\\\\")) OR (process_path:(\\\\\"*\\\\\\\\\\\\\\\\tasksche.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mssecsvc.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskdl.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\WanaDecryptor*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskhsvc.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskse.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\111.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\lhdfrgui.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\diskpart.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\linuxnew.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wannacry.exe\\\\\") AND event_id:\\\\\"4688\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WannaCry-Ransomware-2' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WannaCry Ransomware Activity",
    "version": 1,
    "columns": [],
    "hits": 0,
    "title": "Sigma: WannaCry Ransomware",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*vssadmin delete shadows*\\\\\" \\\\\"*icacls * \\\\\\\\/grant Everyone\\\\\\\\:F \\\\\\\\/T \\\\\\\\/C \\\\\\\\/Q*\\\\\" \\\\\"*bcdedit \\\\\\\\/set \\\\\\\\{default\\\\\\\\} recoveryenabled no*\\\\\" \\\\\"*wbadmin delete catalog \\\\\\\\-quiet*\\\\\")) OR (event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\tasksche.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mssecsvc.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskdl.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\WanaDecryptor*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskhsvc.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskse.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\111.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\lhdfrgui.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\diskpart.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\linuxnew.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wannacry.exe\\\\\")))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:NotPetya-Ransomware-Activity' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects NotPetya ransomware activity in which the extracted passwords are passed back to the main module via named pipe, the file system journal of drive C is deleted and windows eventlogs are cleared using wevtutil",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: NotPetya Ransomware Activity",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND command_line:\\\\\"* cl *\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\wevtutil.exe\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:\\\\\"* deletejournal *\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\fsutil.exe\\\\\") OR (\\\\\"*\\\\\\\\\\\\\\\\perfc.dat*\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\Local\\\\\\\\\\\\\\\\Temp\\\\\\\\* \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\.\\\\\\\\\\\\\\\\pipe\\\\\\\\*\\\\\") OR (event_id:\\\\\"1\\\\\" AND command_line:\\\\\"*.dat,#1\\\\\" AND process_path:\\\\\"*\\\\\\\\\\\\\\\\rundll32.exe\\\\\"))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- 'localhost:9200/.kibana/doc/search:WannaCry-Ransomware-via-Sysmon' <<EOF
{
  "type": "search",
  "search": {
    "description": "Detects WannaCry ransomware activity via Sysmon",
    "version": 1,
    "columns": [
      "command_line",
      "ParentCommandLine"
    ],
    "hits": 0,
    "title": "Sigma: WannaCry Ransomware via Sysmon",
    "sort": [
      "@timestamp",
      "desc"
    ],
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"index\": \"$index_logs__endpoint__winevent__sysmon__X\", \"filter\": [], \"query\": {\"query_string\": {\"query\": \"((event_id:\\\\\"1\\\\\" AND process_path:(\\\\\"*\\\\\\\\\\\\\\\\tasksche.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\mssecsvc.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskdl.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\@WanaDecryptor@*\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskhsvc.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\taskse.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\111.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\lhdfrgui.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\diskpart.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\linuxnew.exe\\\\\" \\\\\"*\\\\\\\\\\\\\\\\wannacry.exe\\\\\")) OR (event_id:\\\\\"1\\\\\" AND command_line:(\\\\\"*vssadmin delete shadows*\\\\\" \\\\\"*icacls * \\\\\\\\/grant Everyone\\\\\\\\:F \\\\\\\\/T \\\\\\\\/C \\\\\\\\/Q*\\\\\" \\\\\"*bcdedit \\\\\\\\/set \\\\\\\\{default\\\\\\\\} recoveryenabled no*\\\\\" \\\\\"*wbadmin delete catalog \\\\\\\\-quiet*\\\\\" \\\\\"*@Please_Read_Me@.txt*\\\\\")))\", \"analyze_wildcard\": true}}, \"highlight\": {\"fields\": {\"*\": {}}, \"require_field_match\": false, \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fragment_size\": 2147483647, \"pre_tags\": [\"@kibana-highlighted-field@\"]}}"
    }
  }
}
EOF
