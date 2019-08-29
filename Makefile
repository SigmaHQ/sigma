.PHONY: test test-rules test-sigmac
TMPOUT = $(shell tempfile||mktemp)
COVSCOPE = tools/sigma/*.py,tools/sigma/backends/*.py,tools/sigmac,tools/merge_sigma
test: clearcov test-rules test-sigmac test-merge build finish

clearcov:
	rm -f .coverage

finish:
	coverage report --fail-under=90
	rm -f $(TMPOUT)

test-rules:
	yamllint rules
	tests/test_rules.py

test-sigmac:
	coverage run -a --include=$(COVSCOPE) tools/sigmac
	coverage run -a --include=$(COVSCOPE) tools/sigmac -h
	coverage run -a --include=$(COVSCOPE) tools/sigmac -l
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvd -t es-qs rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t es-qs rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t es-qs --shoot-yourself-in-the-foot rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c winlogbeat tests/test-modifiers.yml > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -O rulecomment -rvdI -c tools/config/winlogbeat.yml -t es-qs rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t kibana -c tools/config/winlogbeat.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t graylog rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t xpack-watcher -O email,index,webhook -c tools/config/winlogbeat.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t elastalert -c tools/config/winlogbeat.yml -O alert_methods=http_post,email -O emails=test@test.invalid -O http_post_url=http://test.invalid rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t elastalert-dsl -c tools/config/winlogbeat.yml -O alert_methods=http_post,email -O emails=test@test.invalid -O http_post_url=http://test.invalid rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunkxml -c tools/config/splunk-windows.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t logpoint -c tools/config/logpoint-windows.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t wdatp rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t ala rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t ala --backend-config tests/backend_config.yml rules/windows/process_creation/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t es-dsl -c tools/config/winlogbeat.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t powershell -c tools/config/powershell.yml -Ocsv rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t arcsight -c tools/config/arcsight.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t qradar -c tools/config/qradar.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t qualys -c tools/config/qualys.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t netwitness -c tools/config/netwitness.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t sumologic -O rulecomment -c tools/config/sumologic.yml rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml -f 'level>=high,level<=critical,status=stable,logsource=windows,tag=attack.execution' rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml -f 'level>=high,level<=critical,status=xstable,logsource=windows' rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml -f 'level>=high,level<=xcritical,status=stable,logsource=windows' rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml -f 'level=critical' rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml -f 'level=xcritical' rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t splunk -c tools/config/splunk-windows-index.yml -f 'foo=bar' rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-windows.yml -t es-qs rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c sysmon -c logstash-windows -t es-qs rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c sysmon -c logstash-windows -t splunk rules/ > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-windows.yml -c tools/config/generic/sysmon.yml -t es-qs rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-linux.yml -t es-qs rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-windows.yml -t kibana rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-windows.yml -Ooutput=curl -t kibana rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-linux.yml -t kibana rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-linux.yml -Ooutput=curl -t kibana rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-windows.yml -t xpack-watcher rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/logstash-linux.yml -t xpack-watcher rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/filebeat-defaultindex.yml -t xpack-watcher rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/splunk-windows.yml -t splunk rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -c tools/config/generic/sysmon.yml -c tools/config/splunk-windows.yml -t splunk rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t grep rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -rvdI -t fieldlist rules/ > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -t xpack-watcher -c tools/config/winlogbeat.yml -O output=plain -O es=es -O foobar rules/windows/builtin/win_susp_failed_logons_single_source.yml > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -t kibana -c tests/config-multiple_mapping.yml -c tests/config-multiple_mapping-2.yml tests/mapping-conditional-multi.yml > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -t xpack-watcher -c tools/config/winlogbeat.yml -O output=json -O es=es -O foobar rules/windows/builtin/win_susp_failed_logons_single_source.yml > /dev/null
	coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml -o $(TMPOUT) - < tests/collection_repeat.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE)  tools/sigmac -t xpack-watcher -c tools/config/winlogbeat.yml -O output=foobar -O es=es -O foobar rules/windows/builtin/win_susp_failed_logons_single_source.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/not_existing.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/invalid_yaml.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/invalid_sigma-no_identifiers.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/invalid_sigma-no_condition.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/invalid_sigma-invalid_identifier_reference.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/invalid_sigma-invalid_aggregation.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml tests/invalid_sigma-wrong_identifier_definition.yml > /dev/null
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml rules/windows/builtin/win_susp_failed_logons_single_source.yml
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tools/config/winlogbeat.yml -o /not_possible rules/windows/sysmon/sysmon_mimikatz_detection_lsass.yml
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c not_existing rules/windows/sysmon/sysmon_mimikatz_detection_lsass.yml
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tests/invalid_yaml.yml rules/windows/sysmon/sysmon_mimikatz_detection_lsass.yml
	! coverage run -a --include=$(COVSCOPE) tools/sigmac -t es-qs -c tests/invalid_config.yml rules/windows/sysmon/sysmon_mimikatz_detection_lsass.yml

test-merge:
	tests/test-merge.sh
	! coverage run -a --include=$(COVSCOPE) tools/merge_sigma tests/not_existing.yml > /dev/null

test-backend-es-qs:
	tests/test-backend-es-qs.py

build: tools/sigmac tools/merge_sigma tools/sigma/*.py tools/setup.py tools/setup.cfg
	cd tools && python3 setup.py bdist_wheel

upload-test: build
	twine upload --repository-url https://test.pypi.org/legacy/ tools/dist/*

upload: build
	twine upload tools/dist/*

clean:
	cd tools; rm -fr build dist Sigma.egg-info
	find tools/ -type d -name __pycache__ -exec rm -fr {} \;
