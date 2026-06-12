#!/bin/bash
set -euo pipefail

#### Notes ####
# Script to download SCC Tool and configure cscc
# SCC Tool and benchmarks can be found from cyber.mil
# SCC Tool comes with k8s benchmark pre-installed, but we have to manually add the AL2023 STIG benchmark and run cscc for both benchmarks separately.
# As a result, scc only creates a checklist for the k8s STIG, not the AL2023, and instead only outputs a XML file for AL2023.
# This XML file will need to be converted into a checklist file via stigmanger or a custom python script

# Set variables
source_dir="/tmp/cyber-mil-resources"
working_dir="/usr/local/bin"
image_type="$IMAGE_TYPE"
s3_bucket_name="$S3_BUCKET_NAME"

## stig vars
k8s_stig_name="$K8S_STIG_NAME"
al2023_stig_name="$AL2023_STIG_NAME"
scc_os_version="rhel9"

echo "k8s_stig_name: $k8s_stig_name"
echo "al2023_stig_name: $al2023_stig_name"
echo "scc_os_version: $scc_os_version"

## Download SCC and AL2023 STIG benchmark from S3
aws s3 cp --recursive "s3://${s3_bucket_name}/cyber-mil-resources/current" "$source_dir"

# Make SCC dir
mkdir -p "${working_dir}/scc"

# Unzip newly downloaded SCC
unzip "${source_dir}"/scc*"${scc_os_version}"*.zip -d "${working_dir}/scc"

# Untar SCC and remove dir
tar -xf "${working_dir}"/scc/scc*/*.tar.gz -C "${working_dir}/scc" && rm -rf "${working_dir}"/scc/scc-*

## "--listAllBenchmarks" below allows cscc to load any newly downloaded STIGs/SCAPs.
## This also populates the Autoanswer.txt in the ${working_dir}/scc/scc_*/Resources/Content/Manual_Questions/Templates/${rhel_stig}* directory.
# echo "Downloading any new content for cscc"
# $cscc --checkForContentUpdates --installUpdates
# $cscc --listAllBenchmarks
# latest_rhel_stig_version=$(find ${working_dir}/scc/scc_*/Resources/Content/Manual_Questions/Templates/${rhel_stig}* -type f | cut -d "/" -f 11 | cut -d "_" -f 4 | sort -n | tail -n 1)
# echo "Latest RHEL STIG version is ${rhel_stig} ${latest_rhel_stig_version}"
# mv ${source_dir}/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark-enhancedV4.xml /usr/local/bin/scc/scc_5.10.1/Resources/Content/SCAP12_Content/
# rm -rf /usr/local/bin/scc/scc_5.10.1/Resources/Content/SCAP12_Content/U_RHEL_9_V2R2_STIG_SCAP_1-3_Benchmark-enhancedV3.xml
# latest_k8s_stig_version="version:002.004.007"

# Install AL2023 SCAP Content, have to install it inside of SCAP folder here `scc/scc_$scc_version/Resources/Content/SCAP12_Content/`
unzip "${source_dir}"/"U_${al2023_stig_name}_"*_SCAP_*.zip -d "${working_dir}"/scc/scc*/Resources/Content/SCAP12_Content/

export cscc="${working_dir}/scc/scc_*/cscc"

## Configure cscc for AL2023 STIG and run cscc
echo "Configure cscc for ${al2023_stig_name} and run cscc"
$cscc --disableAll
$cscc --enableBenchmark "${al2023_stig_name}_STIG"
$cscc --setProfile MAC-1_Sensitive "$al2023_stig_name"
$cscc --setOpt ignoreCPEOVALResults 1

echo "Running cscc on ${al2023_stig_name}"
$cscc -u "/tmp"

## Configure cscc for K8s STIG and run cscc
if [ "$image_type" != "bastion" ]; then
    echo "Configure cscc for ${k8s_stig_name} and run cscc"
    $cscc --disableAll
    $cscc --enableBenchmark "${k8s_stig_name}_STIG"
    $cscc --setProfile MAC-1_Sensitive "$k8s_stig_name"
    $cscc --setOpt ignoreCPEOVALResults 1

    echo "Running cscc on ${k8s_stig_name}"
    $cscc -u "/tmp"
else
    echo "Image type is ${image_type}, skipping Kubernetes STIG"
fi

echo "Done with scc script"
exit 0
