#!/bin/bash
set -euo pipefail

## Scan OS
export STIG_WORKING_DIR="/home/ec2-user"
export STIG_CYBER_MIL_NAME="U_RHEL_9_V2R4_STIG"
export STIG_SCAP_CYBER_MIL_NAME="${STIG_CYBER_MIL_NAME}_SCAP_1-3_Benchmark"
export STIG_FILES_DIR="oscap_stigs"
export STIG_RESULTS_DIR="oscap_results"

sudo yum install -y scap-security-guide openscap unzip

cd "$STIG_WORKING_DIR"
mkdir -p "$STIG_FILES_DIR"
curl -L "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/${STIG_SCAP_CYBER_MIL_NAME}.zip" -o "$STIG_FILES_DIR/${STIG_SCAP_CYBER_MIL_NAME}.zip"
unzip "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.zip" -d "${STIG_FILES_DIR}/." && rm -rf "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.zip"
sed -i '/platform idref="cpe/d' "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.xml"

mkdir -p "$STIG_RESULTS_DIR"
oscap xccdf eval --report "${STIG_RESULTS_DIR}/${STIG_SCAP_CYBER_MIL_NAME}_result.html" --results "${STIG_RESULTS_DIR}/${STIG_CYBER_MIL_NAME}_xccdf.xml" "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.xml" || true

## Create checklist file
curl -L "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/${STIG_CYBER_MIL_NAME}.zip" -o "${STIG_FILES_DIR}/${STIG_CYBER_MIL_NAME}.zip"

python3 -m ensurepip
python3 -m pip install --upgrade pip
python3 -m pip install -r stig-automations/requirements.txt

python3 stig-automations/stig_combined.py

sed -i "s/Red_Hat_Enterprise_Linux_9/RHEL_9_STIG/g" "$STIG_RESULTS_DIR"/*.ckl

### K8s
export STIG_CYBER_MIL_NAME="U_Kubernetes_V2R3_STIG"
export STIG_SCAP_CYBER_MIL_NAME="${STIG_CYBER_MIL_NAME}_SCAP_1-3_Benchmark"

curl -L "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/${STIG_SCAP_CYBER_MIL_NAME}.zip" -o "$STIG_FILES_DIR/${STIG_SCAP_CYBER_MIL_NAME}.zip"
unzip "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.zip" -d "${STIG_FILES_DIR}/." && rm -rf "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.zip"
sed -i '/platform idref="cpe/d' "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.xml"

oscap xccdf eval --report "${STIG_RESULTS_DIR}/${STIG_SCAP_CYBER_MIL_NAME}_result.html" --results "${STIG_RESULTS_DIR}/${STIG_CYBER_MIL_NAME}_xccdf.xml" "${STIG_FILES_DIR}/${STIG_SCAP_CYBER_MIL_NAME}.xml" || true

curl -L "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/${STIG_CYBER_MIL_NAME}.zip" -o "${STIG_FILES_DIR}/${STIG_CYBER_MIL_NAME}.zip"

python3 stig-automations/stig_combined.py
sed -i "s/>Kubernetes</>Kubernetes_STIG</g" "$STIG_RESULTS_DIR"/*.ckl

bash "$STIG_WORKING_DIR"/stig-automations/stig-checklist-overrides.sh

aws s3 cp --recursive $STIG_RESULTS_DIR/ s3://phil-misc-backups-bucket/results-1/
