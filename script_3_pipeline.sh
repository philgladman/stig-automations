#!/bin/bash
set -euo pipefail

## Set Variables
export STIG_WORKING_DIR="/Users/philgladman/Desktop/home-dir/DevOps/personal/stigs"
export STIG_CYBER_MIL_NAME="U_Kubernetes_V2R6_STIG"
export STIG_FILES_DIR="resources"
export STIG_RESULTS_DIR="results/scc"

pip3 install -r "${STIG_WORKING_DIR}/stig-automations/requirements.txt"

echo "Running convert_xccdf_to_ckl.py to create CKL Checklist file from Results xccdf file..."
python3 "${STIG_WORKING_DIR}/stig-automations/convert_xccdf_to_ckl.py"

echo "Running stig_checklist_overrides.py to apply STIG overrides to new CKL Checklist..."
python3 "${STIG_WORKING_DIR}/stig-automations/stig_checklist_overrides.py"

#### Next step is to set it so after scc creates checklist, it can be fed in to python script