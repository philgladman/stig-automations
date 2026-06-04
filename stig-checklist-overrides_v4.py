#!/usr/bin/env python3
import json
from logging import root
import os
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


ALLOWED_STATUS_VALUES = {
    "Open",
    "Not_Applicable",
    "NotAFinding"
}

formatted_date = datetime.now().strftime("%b_%d_%Y_%H%M%S")
working_dir = os.environ['STIG_WORKING_DIR'] ## /Users/philgladman/Desktop/home-dir/DevOps/personal/stigs
cyber_dot_mil_stig_name = os.environ['STIG_CYBER_MIL_NAME'] ## U_Kubernetes_V2R6_STIG
stig_overrides_dir = os.environ['STIG_OVERRIDES_DIR'] ## overrides/k8s
stig_overrides_dir_full_path = (f"{working_dir}/{stig_overrides_dir}") ## /Users/philgladman/Desktop/home-dir/DevOps/personal/stigs/overrides/k8s
stig_results_dir = os.environ['STIG_RESULTS_DIR'] ## results/scc
stig_result_checklist_input_file = (f"{working_dir}/{stig_results_dir}/{cyber_dot_mil_stig_name}_Jun_02_2026_145207_post_python_script.ckl")
stig_result_checklist_output_file = (f"{working_dir}/{stig_results_dir}/{cyber_dot_mil_stig_name}_Jun_02_2026_145207_post_python_overrides.ckl")

def load_ckl_checks(ckl_file):
    print(f"Loading CKL checks from {ckl_file}")
    ckl_checks = []
    tree = ET.parse(ckl_file)
    root = tree.getroot()
    for vuln in root.findall("./STIGS/iSTIG/VULN"):
        stig_data = {
            item.findtext("VULN_ATTRIBUTE"): item.findtext("ATTRIBUTE_DATA")
            for item in vuln.findall("STIG_DATA")
        }
        rule_ver = stig_data.get("Rule_Ver")
        ckl_checks.append(rule_ver)
        if rule_ver in 

    return ckl_checks

def update_ckl_check():

def load_overrides(overrides_dir, ckl_checks):
    print(f"Loading overrides from {overrides_dir}")
    override_files = sorted(Path(overrides_dir).glob("*.json"))
    if not override_files:
        raise FileNotFoundError(f"No JSON override files found in {overrides_dir}")

    overrides = {}
    for override_file in override_files:
        print(f"Processing override file: {override_file}")
        with override_file.open() as file:
            override_data = json.load(file)

        for check in override_data['stig_checks']:
            # print(f"Processing check_id: {check['check_id']}, status: {check['status']}")
            if check['check_id'] in ckl_checks:
                print(f"Applying override for {check['check_id']}: {check['status']}")
                update_ckl_check(check)
            else:
                print(f"Check ID {check['check_id']} not found in CKL checks. Skipping override.")

    # for override_file in override_files:
    #     with override_file.open() as file:
    #         override_data = json.load(file)

    #     for check in override_data["stig_checks"]:
    #         check_id = check["check_id"]

    #         if check_id in ckl_checks:
    #             print(f"Applying override for {check_id}: {check['status']}")
    #             # update_ckl_check(check)


ckl_checks = load_ckl_checks(stig_result_checklist_input_file)
load_overrides(stig_overrides_dir_full_path, ckl_checks)

# for ckl in ckl_checks:
#     print(ckl)

# for override in overrides:
#     if check_id in ckl_checks:
#         print(f"Applying override for {check_id}: {override['status']}")
        # update_ckl_check(override)
# print(ckl_checks)
# load_overrides(stig_overrides_dir_full_path)

# print("#"*50)
# print(json.dumps(overrides, indent=2))

# apply_overrides(tree, overrides, engineer, allow_missing)
