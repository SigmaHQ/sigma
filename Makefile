    .PHONY: test test-yaml test-sigmac
test: test-yaml test-sigmac

test-yaml:
	yamllint .

test-sigmac:
	tools/sigmac.py -l
	tools/sigmac.py -rvdI -t es-qs rules/
	tools/sigmac.py -rvdI -t kibana rules/
	tools/sigmac.py -rvdI -t xpack-watcher rules/
	tools/sigmac.py -rvdI -t splunk rules/
	tools/sigmac.py -rvdI -t logpoint rules/
	tools/sigmac.py -rvdI -c tools/config/elk-windows.yml -t es-qs rules/
	tools/sigmac.py -rvdI -c tools/config/elk-linux.yml -t es-qs rules/
	tools/sigmac.py -rvdI -c tools/config/elk-windows.yml -t kibana rules/
	tools/sigmac.py -rvdI -c tools/config/elk-linux.yml -t kibana rules/
	tools/sigmac.py -rvdI -c tools/config/elk-windows.yml -t xpack-watcher rules/
	tools/sigmac.py -rvdI -c tools/config/elk-linux.yml -t xpack-watcher rules/
	tools/sigmac.py -rvdI -c tools/config/splunk-windows-all.yml -t splunk rules/
	tools/sigmac.py -rvdI -c tools/config/logpoint-windows-all.yml -t logpoint rules/
	tools/sigmac.py -rvdI -t grep rules/
	tools/sigmac.py -rvdI -t fieldlist rules/
