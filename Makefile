.PHONY: test test-yaml test-sigmac
test: test-yaml test-sigmac

test-yaml:
	yamllint .

test-sigmac:
	tools/sigmac.py -l
	tools/sigmac.py -rvdI -t es-qs rules/ 
	tools/sigmac.py -rvdI -t splunk rules/ 
	tools/sigmac.py -rvdI -t logpoint rules/ 
	tools/sigmac.py -rvdI -t fieldlist rules/ 
