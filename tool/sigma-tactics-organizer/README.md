# sigma-tactics-organizer
Script that organize Sigma rules by MITRE | ATT&amp;CK tactics and techniques. 
With this simple script you will have all the rules organized in 2 main folders (`tactics` and `techniques`) and many sub-folders for different typology.

```
mitre
  --> tactics
          --> TA0043_reconnaissance
          --> TA0042_resource_development
          --> ...
  --> techniques
          --> T1002
          --> T1006
          --> ...
```

![image](https://github.com/dan21san/sigma-tactics-organizer/assets/98960305/d4666727-7f7d-4f96-afa2-34aa1102bd1e)


The script considers as input path `sigma/rules/` and as the output path `sigma/rules/mitre`. This can be easily modified by changing the following lines of the scripts 

`root_directory = script_directory+'/../../rules'`  
`destination_base_directory = script_directory+'/../../rules/mitre'`


## Example
from shell:
```bash
$ python3 rules-mitre-organizer.py
```

## References
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
