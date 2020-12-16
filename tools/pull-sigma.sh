#ls -la "${ESALERT_HOME}"/rules/sigma_sysmon_"$(basename "${rule}")"
# *********** Unsupported SIGMA Functions ***************
# Unsupported feature "near" aggregation operator not yet implemented https://github.com/Neo23x0/sigma/issues/209
SIGMAremoveNearRules() {
    if grep --quiet -E "\s+condition/\s+.*\s+|\s+near\s+" "$1"; then
        echo "[---] Skipping incompatible rule $1, reference: https://github.com/Neo23x0/sigma/issues/209"
        #rm "$1"
        return 0
    else
      return 1
    fi
}

# ******* Transforming every Windows SIGMA rule to elastalert rules *******

echo " "
echo "Translating SIGMA rules to Elastalert format.."
echo "------------------------------------------------"
echo " "
rule_counter=0
ESALERT_HOME="../elastalert_rules"
# # Windows rules
# for  rule_category in ../rules/windows/* ; do
#     echo " "
#     echo "Working on Folder: $rule_category:"
#     echo "-------------------------------------------------------------"
#     if [ "$rule_category" == ../rules/windows/process_creation ]; then
#         for rule in $rule_category/* ; do
#             if [ $rule != ../rules/windows/process_creation/win_mal_adwind.yml ];
#             then
#                 if SIGMAremoveNearRules "$rule"; then
#                     continue
#                 else
#                     echo "[+++] Processing Windows process creation rule: $rule .."
#                     ./sigmac -t elastalert -c config/generic/sysmon.yml -c config/wazuh.yml -o "${ESALERT_HOME}"/sigma_"$(basename "$rule")" "$rule"
#                     # Give unique rule name for sysmon
#                     sed -i '' 's/^name: /name: Sysmon_/' "${ESALERT_HOME}"/sigma_sysmon_"$(basename "$rule")"
#                     ./sigmac -t elastalert -c config/generic/windows-audit.yml -c config/wazuh.yml -o ${ESALERT_HOME}/sigma_sysmon_"$(basename "$rule")" "$rule"
#                     #ls -la "${ESALERT_HOME}"/rules/sigma_sysmon_"$(basename "${rule}")"
#                     rule_counter=$[$rule_counter +1]
#                 fi
#             fi
#         done
#     else
#         for rule in $rule_category/* ; do
#             if SIGMAremoveNearRules "$rule"; then
#                 continue
#             else
#                 echo "[+++] Processing additional Windows rule: $rule .."
#                 ./sigmac -t elastalert -c config/wazuh.yml -o "${ESALERT_HOME}"/sigma_"$(basename "$rule")" "$rule"rules/sigma_"$(basename "$rule")" $rule
#                 sed -i '' "s/^name: .*/name: sigma_"$(basename -s .yml "$rule")"/" "${ESALERT_HOME}"/sigma_"$(basename "$rule")"
#                 rule_counter=$[$rule_counter +1]
#             fi
#         done
#     fi
# done
# Apt rules
echo " "
echo "Working on Folder: apt:"
echo "-------------------------------------------------------------"
for rule in ../rules/apt/* ; do
    if SIGMAremoveNearRules "$rule"; then
        continue
    else
        echo "[+++] Processing apt rule: $rule .."
        ./sigmac -t elastalert -c config/generic/sysmon.yml -c config/wazuh.yml -o "${ESALERT_HOME}"/sigma_apt_"$(basename "$rule")" "$rule"
        # Give unique rule name for sysmon
        sed -i '' 's/^name: /name: Sysmon_/' "${ESALERT_HOME}"/sigma_sysmon_apt_"$(basename "$rule")"
        ./sigmac -t elastalert -c config/generic/windows-audit.yml -c config/wazuh.yml -o "${ESALERT_HOME}"/sigma_sysmon_apt_"$(basename "$rule")" "$rule"
        rule_counter=$[$rule_counter +1]
    fi
done
echo "-------------------------------------------------------"
echo "[+++] Finished processing $rule_counter SIGMA rules"
echo "-------------------------------------------------------"
echo " "

# ******* Removing Rules w/ Too Many False Positives *****************************
echo "Removing Elastalert rules that generate too much noise. Replacing them with HELK rules.."
echo "--------------------------------------------------------------------------------------------"


# Patching one issue in SIGMA Integration
# References:
# ONE SIGMA Rule & TWO log sources: https://github.com/Neo23x0/sigma/issues/205


# ******** Deleting Empty Files ***********
echo " "
echo "Removing empty files.."
echo "-------------------------"
rule_counter=0
for ef in $ESALERT_HOME/* ; do
    if [[ -s $ef ]]; then
        continue
    else
        echo "[---] Removing empty file $ef.."
        rm $ef
        rule_counter=$[$rule_counter +1]
    fi
done
echo "--------------------------------------------------------------"
echo "[+++] Finished deleting $rule_counter empty Elastalert rules"
echo "--------------------------------------------------------------"
echo " "

rule_counter=0
echo "Fixing Elastalert rule files with multiple SIGMA rules in them.."
echo "------------------------------------------------------------------"
for er in $ESALERT_HOME/*; do
    echo "[+++] Identifiying extra new lines in file $er .."
    counter=0
    while read line; do
        if [ "$line" == "" ]; then
            counter=$[$counter +1]
        fi
    done < $er

    if [ "$counter" == "2" ] ; then
        echo "[++++++] Truncating file $er with $counter lines .."
        truncate -s -2 $er
    elif [ "$counter" == "3" ]; then
        echo "[++++++] Truncating file $er with $counter lines .."
        truncate -s -2 $er
        # https://github.com/Neo23x0/sigma/issues/205
        echo "[++++++] Spliting file $er in two files .."
        name=$(basename $er .yml)
        awk -v RS= -v filename="$name" '{print > ("../elastalert_rules/"filename NR ".yml")}' $er
        echo "[------] Removing original file $er .."
        rm $er
        rule_counter=$[$rule_counter +1]
    fi
done
echo "---------------------------------------------------------"
echo "[+++] Finished splitting $rule_counter Elastalert rules"
echo "---------------------------------------------------------"
echo " "
