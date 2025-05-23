#!/bin/bash
set -euo pipefail

# "Global" Variables
todays_date=$(date +'%m-%d-%Y')
engineers_initials="rap_pipeline"
status_fail="Open"
status_not_applicable="Not_Applicable"
status_pass="NotAFinding"
old_comment="<COMMENTS />"
old_status="<STATUS>.*</STATUS>"
# ami_name="$AMI_NAME"
ami_name="rap-test-ami"
old_target_comment="TARGET_COMMENT></TARGET_COMMENT>"
new_target_comment="TARGET_COMMENT>AMI_NAME: $ami_name</TARGET_COMMENT>"

## RHEL9 STIG Variables
rhel9_stig_path=$(ls "${STIG_WORKING_DIR}"/"${STIG_RESULTS_DIR}"/U_RHEL_9_*.ckl)
rhel9_cat_1_json=$(cat /home/ec2-user/test-overrides/rhel/cat_1_overrides.json)
rhel9_cat_2_json=$(cat /home/ec2-user/test-overrides/rhel/cat_2_overrides.json)
rhel9_cat_3_json=$(cat /home/ec2-user/test-overrides/rhel/cat_3_overrides.json)
k8s_stig_path=$(ls "${STIG_WORKING_DIR}"/"${STIG_RESULTS_DIR}"/U_Kubernetes_*.ckl)
k8s_cat_1_json=$(cat /home/ec2-user/test-overrides/k8s/cat_1_overrides.json)
k8s_cat_2_json=$(cat /home/ec2-user/test-overrides/k8s/cat_2_overrides.json)
# rhel9_stig_path=$(ls /Users/philgladman/Desktop/stigs/oscap_results_files/U_RHEL_9_*.ckl)
# rhel9_cat_1_json=$(cat /Users/philgladman/Desktop/stigs/overrides/rhel9_stig_overrides/cat_1_overrides.json)
# rhel9_cat_2_json=$(cat /Users/philgladman/Desktop/stigs/overrides/rhel9_stig_overrides/cat_2_overrides.json)
# rhel9_cat_3_json=$(cat /Users/philgladman/Desktop/stigs/overrides/rhel9_stig_overrides/cat_3_overrides.json)

## K8S STIG Variables
### SCC Tool does not create a STIG Checklist, to get around this we manually create a Base/Blank Checklist
# k8s_report_path=$(ls /tmp/Sessions/*/Results/SCAP/*All-Settings_Kubernetes*.html)
# k8s_stig_path_prefix=$(echo $k8s_report_path | cut -d "/" -f 7 | cut -d "_" -f -4)
# k8s_stig_path="/packer/${k8s_stig_path_prefix}_Kubernetes_STIG.ckl"
# k8s_base_stig_path=$(ls /packer/cyber-mil-resources/U_Kubernetes_*.ckl)
# cp "$k8s_base_stig_path" "$k8s_stig_path"
# k8s_stig_path=$(ls /Users/philgladman/Desktop/stigs/oscap_results_files/U_Kubernetes_*.ckl)
# k8s_cat_1_json=$(cat /Users/philgladman/Desktop/stigs/overrides/k8s_stig_overrides/cat_1_overrides.json)
# k8s_cat_2_json=$(cat /Users/philgladman/Desktop/stigs/overrides/k8s_stig_overrides/cat_2_overrides.json)

function override_stig_check() {
  local id="$1"
  local comment="$2"
  local status="$3"
  local stig_path="$4"

  if [[ $status == "Fail" ]]; then
    official_status="$status_fail"
  elif [[ $status == "NA" ]]; then
    official_status="$status_not_applicable"
  elif [[ $status == "Pass" ]]; then
    official_status="$status_pass"
  else
    echo "ERROR - $status is an incorrect status type"
    exit 1
  fi

  # comment_details=$(grep "$id" "$stig_path" -A 200 -n | grep "$old_comment" | head -n 1 | grep -o "^[0-9]*" || true)
  original_stig_data=$(grep -Pzo -m 1 "(?s)${id}.*?</VULN>" "$stig_path" | tr -d '\000')
  if [ -z "$original_stig_data" ]; then
    echo "ERROR - stig_check_id: ${id} does not exist"
    exit 1
  fi

  ## Using "@" character as sed delimiter to avoid collisions with other special characters.
#   echo "############################################"
#   echo "original_stig_data"
#   echo "$original_stig_data"
#   echo "############################################"
  formatted_original_stig_data=$(echo "$original_stig_data" | sed 's|\@|\\@|g' |sed 's@\*@\\*@g' | sed 's@\"@\\"@g' | sed 's@\$@\\$@g' | sed 's@\[@\\[@g' | sed 's@\]@\\]@g' | sed 's@\&@\\&@g' | sed "s/\\\n/\\\\\\\n/g" | sed 's@\%@\\%@g' | sed -z 's@\n@\\n@g' | sed 's@</VULN>\\n@</VULN>@g')
  new_comment="<COMMENTS>${status} - ${todays_date}-${engineers_initials} - evidence: ${comment}</COMMENTS>"
  new_status="<STATUS>${official_status}</STATUS>"
  new_stig_data=$(echo "$formatted_original_stig_data" | sed "s@${old_comment}@${new_comment}@g" | sed "s@${old_status}@${new_status}@g")
#   echo "############################################"
#   echo "formatted_original_stig_data"
#   echo "$formatted_original_stig_data"
#   echo "############################################"
#   echo "############################################"
#   echo "new_stig_data"
#   echo "$new_stig_data"
#   echo "############################################"
#   Comment below for debugging
#   echo "############################################"
#   echo "grep"
#   grep -Poz "$formatted_original_stig_data" "$stig_path"  | tr -d '\000'
#   echo "############################################"
#   echo "############################################"
#   echo "sed"
  sed -zi "s@${formatted_original_stig_data}@${new_stig_data}@g" "$stig_path"
#   echo "############################################"
}

function override_stigs() {
  local stig_checks_json="$1"
  local stig_path="$2"

  sed -Ei "s/^[[:space:]]+$//g" "$stig_path"
  stig_checks_ids=($(echo "$stig_checks_json" | jq -r ".stig_checks[].check_id"))
  for id in "${stig_checks_ids[@]}"; do
    check_data=$(echo "$stig_checks_json" | jq ".stig_checks[] | select(.check_id==\"$id\")")
    status=$(echo "$check_data" | jq -r ".status")
    comment=$(echo "$check_data" | jq -r ".comment")
    echo "overriding stig_check $id"
    override_stig_check "$id" "$comment" "$status" "$stig_path"
  done
}

echo "### overriding RHEL9 CAT 1 stig checks ###"
override_stigs "$rhel9_cat_1_json" "$rhel9_stig_path"

echo "### overriding RHEL9 CAT 2 stig checks ###"
override_stigs "$rhel9_cat_2_json" "$rhel9_stig_path"

echo "### overriding RHEL9 CAT 3 stig checks ###"
override_stigs "$rhel9_cat_3_json" "$rhel9_stig_path"

echo "Adding AMI Name to RHEL9 stig checklist file"
sed -i "s|$old_target_comment|$new_target_comment|g" "$rhel9_stig_path"

echo "### overriding K8S CAT 1 stig checks ###"
override_stigs "$k8s_cat_1_json" "$k8s_stig_path"

echo "### overriding K8S CAT 2 stig checks ###"
override_stigs "$k8s_cat_2_json" "$k8s_stig_path"

echo "Adding AMI Name to K8S stig checklist file"
sed -i "s|$old_target_comment|$new_target_comment|g" "$k8s_stig_path"

echo "SUCCESS - Done with script"
exit 0
