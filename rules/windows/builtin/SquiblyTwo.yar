title: SquiblyTwo  
status: experimental
description: Detects WMI SquiblyTwo Attack
references:
    - https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html 
author: Markus Neis 
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image:
            - '*\wmic.exe'
        CommandLine:
            - 'wmic*os*get*/format:\"http*'
    condition: 1 of selection
falsepositives:
    - Unknown 
level: medium
