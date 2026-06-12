import json
import os
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

# export STIG_WORKING_DIR="/Users/philgladman/Desktop/home-dir/DevOps/personal/stigs"
# export STIG_CYBER_MIL_NAME="U_Kubernetes_V2R6_STIG"
# export STIG_OVERRIDES_DIR="overrides/k8s"
# export STIG_RESULTS_DIR="results/scc"

formatted_date = datetime.now().strftime("%b_%d_%Y_%H%M%S")
todays_date = datetime.now().strftime("%m-%d-%Y")
working_dir = os.environ['STIG_WORKING_DIR'] ## /Users/philgladman/Desktop/home-dir/DevOps/personal/stigs
cyber_dot_mil_stig_name = os.environ['STIG_CYBER_MIL_NAME'] ## U_Kubernetes_V2R6_STIG
stig_overrides_dir = os.environ['STIG_OVERRIDES_DIR'] ## overrides/k8s
stig_overrides_dir_full_path = (f"{working_dir}/{stig_overrides_dir}") ## /Users/philgladman/Desktop/home-dir/DevOps/personal/stigs/overrides/k8s
stig_results_dir = os.environ['STIG_RESULTS_DIR'] ## results/scc
stig_result_checklist_input_file = (f"{working_dir}/{stig_results_dir}/{cyber_dot_mil_stig_name}_without_overrides.ckl")
stig_result_checklist_output_file = (f"{working_dir}/{stig_results_dir}/{cyber_dot_mil_stig_name}_with_overrides.ckl")
engineer = os.environ.get("STIG_OVERRIDE_ENGINEER", "REPLACE_ME_pipeline")


# Check if it exists (file or directory)
if os.path.exists(stig_overrides_dir_full_path):
    print(f"Path exists: {stig_overrides_dir_full_path}")
else:
    print(f"Path does not exist: {stig_overrides_dir_full_path}")
    exit(1)

if os.path.exists(stig_result_checklist_input_file):
    print(f"Path exists: {stig_result_checklist_input_file}")
else:
    print(f"Path does not exist: {stig_result_checklist_input_file}")
    exit(1)


## Load all json override files into a combined list
def load_overrides(overrides_dir):
    override_files = sorted(Path(overrides_dir).glob("*.json"))
    override_checks = []

    for file in override_files:
        print(f"Processing override file: {file}")
        with file.open() as f:
            override_data = json.load(f)
        override_checks.extend(override_data['stig_checks'])

    return override_checks

## Function to get "Rule_Ver" (AKA check_id) from CKL checklist
def get_rule_version(vuln):
    for stig_data in vuln.findall("STIG_DATA"):
        if stig_data.findtext("VULN_ATTRIBUTE") == "Rule_Ver":
            return stig_data.findtext("ATTRIBUTE_DATA")
    return None

## Function to apply override from json file to CKL checklist
def apply_override(override_check, ckl_root, date, users_name):
    for vuln in ckl_root.findall("./STIGS/iSTIG/VULN"):
        rule_ver = get_rule_version(vuln)

        if rule_ver == override_check['check_id']:
            new_status = override_check['status']
            new_comment = (
                f"{override_check['status']} - {date}-{users_name} - "
                f"evidence: {override_check['comment']}"
            )
            print(f"Overwriting {rule_ver}: to {new_status}")
            vuln.find("STATUS").text = new_status
            vuln.find("COMMENTS").text = new_comment
            return True

override_checks = load_overrides(stig_overrides_dir_full_path)

## Load CKL checklist
tree = ET.parse(stig_result_checklist_input_file)
root = tree.getroot()

## Loop over each override check, if check found in CKL Checklist, update status and comment
for override_check in override_checks:
    if not apply_override(override_check, root, todays_date, engineer):
        print(
            f"WARN: Check ID {override_check['check_id']} not found in CKL checklist. "
            "Check may be deprecated. Skipping override."
        )

## Write updated CKL checklist to new file
ET.indent(tree, space="\t")
tree.write(stig_result_checklist_output_file, encoding='UTF-8', xml_declaration=True, short_empty_elements=False)
