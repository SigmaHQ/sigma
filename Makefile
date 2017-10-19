    .PHONY: test test-yaml test-sigmac
test: test-yaml test-sigmac

test-yaml:
	yamllint .

test-sigmac:
	rm -f .coverage
	coverage run -a --include=tools/* tools/sigmac.py -l
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t es-qs rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t kibana rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t xpack-watcher rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t splunk rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t logpoint rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/elk-windows.yml -t es-qs rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/elk-linux.yml -t es-qs rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/elk-windows.yml -t kibana rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/elk-linux.yml -t kibana rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/elk-windows.yml -t xpack-watcher rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/elk-linux.yml -t xpack-watcher rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/splunk-windows-all.yml -t splunk rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -c tools/config/logpoint-windows-all.yml -t logpoint rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t grep rules/
	coverage run -a --include=tools/* tools/sigmac.py -rvdI -t fieldlist rules/
	coverage report --fail-under=80
