# Static data required by backends

sysmon_schema = """
<manifest schemaversion="4.2" binaryversion="8.00">
  <configuration>
    <options>
      <!-- Command-line only options -->
      <option switch="i" name="Install" argument="optional" noconfig="true" exclusive="true" />
      <option switch="c" name="Configuration" argument="optional" noconfig="true" exclusive="true" />
      <option switch="u" name="UnInstall" argument="none" noconfig="true" exclusive="true" />
      <option switch="m" name="Manifest" argument="none" noconfig="true" exclusive="true" />
      <option switch="t" name="DebugMode" argument="none" noconfig="true" />
      <option switch="s" name="PrintSchema" argument="optional" noconfig="true" exclusive="true" />
      <option switch="nologo" name="NoLogo" argument="none" noconfig="true" />
      <option switch="accepteula" name="AcceptEula" argument="none" noconfig="true" />
      <option switch="-" name="ConfigDefault" argument="none" noconfig="true" />
      <!-- Configuration file -->
      <option switch="h" name="HashAlgorithms" argument="required" />
      <option switch="n" name="NetworkConnect" argument="optional" rule="true" />
      <option switch="l" name="ImageLoad" argument="optional" rule="true" />
      <option switch="d" name="DriverName" argument="required" />
      <option switch="k" name="ProcessAccess" argument="required" rule="true" forceconfig="true" />
      <option switch="r" name="CheckRevocation" argument="none" />
      <option switch="g" name="PipeMonitoring" argument="required" rule="true" forceconfig="true" />
    </options>
    <filters default="is">is,is not,contains,excludes,begin with,end with,less than,more than,image</filters>
  </configuration>
  <events>
    <event name="SYSMON_ERROR" value="255" level="Error" template="Error report" version="3">
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ID" inType="win:UnicodeString" outType="xs:string" />
      <data name="Description" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_CREATE_PROCESS" value="1" level="Informational" template="Process Create" rulename="ProcessCreate" ruledefault="include" version="5">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="FileVersion" inType="win:UnicodeString" outType="xs:string" />
      <data name="Description" inType="win:UnicodeString" outType="xs:string" />
      <data name="Product" inType="win:UnicodeString" outType="xs:string" />
      <data name="Company" inType="win:UnicodeString" outType="xs:string" />
      <data name="CommandLine" inType="win:UnicodeString" outType="xs:string" />
      <data name="CurrentDirectory" inType="win:UnicodeString" outType="xs:string" />
      <data name="User" inType="win:UnicodeString" outType="xs:string" />
      <data name="LogonGuid" inType="win:GUID" />
      <data name="LogonId" inType="win:HexInt64" />
      <data name="TerminalSessionId" inType="win:UInt32" />
      <data name="IntegrityLevel" inType="win:UnicodeString" outType="xs:string" />
      <data name="Hashes" inType="win:UnicodeString" outType="xs:string" />
      <data name="ParentProcessGuid" inType="win:GUID" />
      <data name="ParentProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="ParentImage" inType="win:UnicodeString" outType="xs:string" />
      <data name="ParentCommandLine" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_FILE_TIME" value="2" level="Informational" template="File creation time changed" rulename="FileCreateTime" ruledefault="include" version="4">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetFilename" inType="win:UnicodeString" outType="xs:string" />
      <data name="CreationUtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="PreviousCreationUtcTime" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_NETWORK_CONNECT" value="3" level="Informational" template="Network connection detected" rulename="NetworkConnect" version="5">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="User" inType="win:UnicodeString" outType="xs:string" />
      <data name="Protocol" inType="win:UnicodeString" outType="xs:string" />
      <data name="Initiated" inType="win:Boolean" />
      <data name="SourceIsIpv6" inType="win:Boolean" />
      <data name="SourceIp" inType="win:UnicodeString" outType="xs:string" />
      <data name="SourceHostname" inType="win:UnicodeString" outType="xs:string" />
      <data name="SourcePort" inType="win:UInt16" />
      <data name="SourcePortName" inType="win:UnicodeString" outType="xs:string" />
      <data name="DestinationIsIpv6" inType="win:Boolean" />
      <data name="DestinationIp" inType="win:UnicodeString" outType="xs:string" />
      <data name="DestinationHostname" inType="win:UnicodeString" outType="xs:string" />
      <data name="DestinationPort" inType="win:UInt16" />
      <data name="DestinationPortName" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_SERVICE_STATE_CHANGE" value="4" level="Informational" template="Sysmon service state changed" version="3">
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="State" inType="win:UnicodeString" outType="xs:string" />
      <data name="Version" inType="win:UnicodeString" outType="xs:string" />
      <data name="SchemaVersion" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_PROCESS_TERMINATE" value="5" level="Informational" template="Process terminated" rulename="ProcessTerminate" ruledefault="include" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_DRIVER_LOAD" value="6" level="Informational" template="Driver loaded" rulename="DriverLoad" ruledefault="include" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ImageLoaded" inType="win:UnicodeString" outType="xs:string" />
      <data name="Hashes" inType="win:UnicodeString" outType="xs:string" />
      <data name="Signed" inType="win:UnicodeString" outType="xs:string" />
      <data name="Signature" inType="win:UnicodeString" outType="xs:string" />
      <data name="SignatureStatus" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_IMAGE_LOAD" value="7" level="Informational" template="Image loaded" rulename="ImageLoad" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="ImageLoaded" inType="win:UnicodeString" outType="xs:string" />
      <data name="FileVersion" inType="win:UnicodeString" outType="xs:string" />
      <data name="Description" inType="win:UnicodeString" outType="xs:string" />
      <data name="Product" inType="win:UnicodeString" outType="xs:string" />
      <data name="Company" inType="win:UnicodeString" outType="xs:string" />
      <data name="Hashes" inType="win:UnicodeString" outType="xs:string" />
      <data name="Signed" inType="win:UnicodeString" outType="xs:string" />
      <data name="Signature" inType="win:UnicodeString" outType="xs:string" />
      <data name="SignatureStatus" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_CREATE_REMOTE_THREAD" value="8" level="Informational" template="CreateRemoteThread detected" rulename="CreateRemoteThread" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="SourceProcessGuid" inType="win:GUID" />
      <data name="SourceProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="SourceImage" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetProcessGuid" inType="win:GUID" />
      <data name="TargetProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="TargetImage" inType="win:UnicodeString" outType="xs:string" />
      <data name="NewThreadId" inType="win:UInt32" />
      <data name="StartAddress" inType="win:UnicodeString" outType="xs:string" />
      <data name="StartModule" inType="win:UnicodeString" outType="xs:string" />
      <data name="StartFunction" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_RAWACCESS_READ" value="9" level="Informational" template="RawAccessRead detected" rulename="RawAccessRead" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="Device" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_ACCESS_PROCESS" value="10" level="Informational" template="Process accessed" rulename="ProcessAccess" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="SourceProcessGUID" inType="win:GUID" />
      <data name="SourceProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="SourceThreadId" inType="win:UInt32" />
      <data name="SourceImage" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetProcessGUID" inType="win:GUID" />
      <data name="TargetProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="TargetImage" inType="win:UnicodeString" outType="xs:string" />
      <data name="GrantedAccess" inType="win:HexInt32" />
      <data name="CallTrace" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_FILE_CREATE" value="11" level="Informational" template="File created" rulename="FileCreate" ruledefault="include" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetFilename" inType="win:UnicodeString" outType="xs:string" />
      <data name="CreationUtcTime" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_REG_KEY" value="12" level="Informational" template="Registry object added or deleted" rulename="RegistryEvent" ruledefault="include" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventType" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetObject" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_REG_SETVALUE" value="13" level="Informational" template="Registry value set" rulename="RegistryEvent" ruledefault="include" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventType" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetObject" inType="win:UnicodeString" outType="xs:string" />
      <data name="Details" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_REG_NAME" value="14" level="Informational" template="Registry object renamed" rulename="RegistryEvent" ruledefault="include" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventType" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetObject" inType="win:UnicodeString" outType="xs:string" />
      <data name="NewName" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_FILE_CREATE_STREAM_HASH" value="15" level="Informational" template="File stream created" rulename="FileCreateStreamHash" ruledefault="include" version="2">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
      <data name="TargetFilename" inType="win:UnicodeString" outType="xs:string" />
      <data name="CreationUtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="Hash" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_SERVICE_CONFIGURATION_CHANGE" value="16" level="Informational" template="Sysmon config state changed" version="3">
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="Configuration" inType="win:UnicodeString" outType="xs:string" />
      <data name="ConfigurationFileHash" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_CREATE_NAMEDPIPE" value="17" level="Informational" template="Pipe Created" rulename="PipeEvent" ruledefault="exclude" version="1">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="PipeName" inType="win:UnicodeString" outType="xs:string" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_CONNECT_NAMEDPIPE" value="18" level="Informational" template="Pipe Connected" rulename="PipeEvent" ruledefault="exclude" version="1">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
      <data name="PipeName" inType="win:UnicodeString" outType="xs:string" />
      <data name="Image" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_WMI_FILTER" value="19" level="Informational" template="WmiEventFilter activity detected" rulename="WmiEvent" ruledefault="exclude" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventType" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="Operation" inType="win:UnicodeString" outType="xs:string" />
      <data name="User" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventNamespace" inType="win:UnicodeString" outType="xs:string" />
      <data name="Name" inType="win:UnicodeString" outType="xs:string" />
      <data name="Query" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_WMI_CONSUMER" value="20" level="Informational" template="WmiEventConsumer activity detected" rulename="WmiEvent" ruledefault="exclude" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventType" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="Operation" inType="win:UnicodeString" outType="xs:string" />
      <data name="User" inType="win:UnicodeString" outType="xs:string" />
      <data name="Name" inType="win:UnicodeString" outType="xs:string" />
      <data name="Type" inType="win:UnicodeString" outType="xs:string" />
      <data name="Destination" inType="win:UnicodeString" outType="xs:string" />
    </event>
    <event name="SYSMON_WMI_BINDING" value="21" level="Informational" template="WmiEventConsumerToFilter activity detected" rulename="WmiEvent" ruledefault="exclude" version="3">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="EventType" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="Operation" inType="win:UnicodeString" outType="xs:string" />
      <data name="User" inType="win:UnicodeString" outType="xs:string" />
      <data name="Consumer" inType="win:UnicodeString" outType="xs:string" />
      <data name="Filter" inType="win:UnicodeString" outType="xs:string" />
    </event>
  </events>
</manifest>
"""
