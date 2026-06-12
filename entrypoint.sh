#!/bin/bash
set -euo pipefail

#### Notes ####
# Script to do the following
# Run scc tool against K8S and AL2023 STIGs, and create xccdf.xml result files
# Run python script to convert xccdf.xml into .ckl checklist file
# Run python script to add overrides to .ckl checklist file
# Upload results to S3

## Set Global Variables
export STIG_WORKING_DIR="$(pwd)"
export STIG_FILES_DIR="cyber-mil-resources"
export STIG_RESULTS_DIR="results"
export IMAGE_TYPE="$IMAGE_TYPE"
export S3_BUCKET_NAME="$S3_BUCKET_NAME"
export K8S_STIG_NAME="Kubernetes"
export AL2023_STIG_NAME="Amazon_Linux_2023"

## Set Local Variables
instance_id=$(cat /var/lib/cloud/data/instance-id)
instance_ami_id=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[].Instances[].ImageId" --output text)
formatted_date=$(date +"%Y-%m-%d")

## Run scc.sh
echo "Running scc script..."
bash "${STIG_WORKING_DIR}/scc.sh"

## Download cyber.mil resources form S3
mkdir -p "${STIG_WORKING_DIR}"
mkdir -p "${STIG_WORKING_DIR}/${STIG_RESULTS_DIR}"
aws s3 cp --recursive "s3://${S3_BUCKET_NAME}/cyber-mil-resources/current" "${STIG_WORKING_DIR}/${STIG_FILES_DIR}"

## Install required modules
python3 -m ensurepip --upgrade
python3 -m pip install --upgrade pip
python3 -m pip install -r "${STIG_WORKING_DIR}/requirements.txt"

## AL2023 STIG
export STIG_CYBER_MIL_NAME="U_Amazon_Linux_2023_V1R3_STIG"
export STIG_OVERRIDES_DIR="overrides/al2023"

echo "Starting on ${STIG_CYBER_MIL_NAME} with ${STIG_OVERRIDES_DIR} overrides"

## Get applicable xccdf results file from SCC tool
cp /tmp/Sessions/*/Results/SCAP/XML/*${AL2023_STIG_NAME}*.xml "${STIG_WORKING_DIR}/${STIG_RESULTS_DIR}/${STIG_CYBER_MIL_NAME}_scc_result_xccdf.xml"

echo "Running convert_xccdf_to_ckl.py to create CKL Checklist file from Results xccdf file..."
python3 "${STIG_WORKING_DIR}/convert_xccdf_to_ckl.py"

echo "Running stig_checklist_overrides.py to apply STIG overrides to new CKL Checklist..."
python3 "${STIG_WORKING_DIR}/stig_checklist_overrides.py"

## Kubernetes STIG
if [ "$IMAGE_TYPE" != "bastion" ]; then
    export STIG_CYBER_MIL_NAME="U_Kubernetes_V2R6_STIG"
    export STIG_OVERRIDES_DIR="overrides/k8s"

    echo "Starting on ${STIG_CYBER_MIL_NAME} with ${STIG_OVERRIDES_DIR} overrides"

    ## Get applicable xccdf results file from SCC tool
    cp /tmp/Sessions/*/Results/SCAP/XML/*${K8S_STIG_NAME}*.xml "${STIG_WORKING_DIR}/${STIG_RESULTS_DIR}/${STIG_CYBER_MIL_NAME}_scc_result_xccdf.xml"

    echo "Running convert_xccdf_to_ckl.py to create CKL Checklist file from Results xccdf file..."
    python3 "${STIG_WORKING_DIR}/convert_xccdf_to_ckl.py"

    echo "Running stig_checklist_overrides.py to apply STIG overrides to new CKL Checklist..."
    python3 "${STIG_WORKING_DIR}/stig_checklist_overrides.py"
else
    echo "Image type is ${IMAGE_TYPE}, skipping Kubernetes STIG"
fi

aws s3 cp --recursive "${STIG_WORKING_DIR}/${STIG_RESULTS_DIR}" "s3://${S3_BUCKET_NAME}/stig-result/${IMAGE_TYPE}/${formatted_date}/${instance_ami_id}/"
echo "Script complete"
exit 0
