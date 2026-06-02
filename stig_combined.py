#### Python script to do the following
#### 1.) Create a base/empty STIG Checklist .ckl file from DISA STIG ZIP File
#### 2.) Read xccdf.xml results file. This files is the output of running oscap
#### 3.) Populates the new STIG Checklist file with the results from the xccdf.xml file
#### Final product is a filled out DISA STIG Checklist .ckl file
#### oscap installation - `sudo yum install scap-security-guide openscap`
#### SCAP Benchmark - wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.zip
#### STIG Checklist - wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R3_STIG.zip
#### Remove CPE form xml file so RHEL9 will run against AL2023
##### oscap xccdf eval --report test.html --stig-viewer test.ckl --results test-xccdf.xml /home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark-updated.xml
##### NEXT STEPS - Currently this will pull create a empty checklist file, and then read in a xccdf.xml with scan results and convert that to a
##### simple json/dictionary. Next step is work on updating the stig checklist with the status of the scan results
import os
import xmltodict
import json
from stig_parser import convert_xccdf, generate_ckl, generate_ckl_file
from datetime import datetime
import xml.etree.ElementTree as ET

formatted_date = datetime.now().strftime("%b_%d_%Y_%H%M%S")
working_dir = os.environ['STIG_WORKING_DIR']
cyber_dot_mil_stig_name = os.environ['STIG_CYBER_MIL_NAME']
stig_files_dir = os.environ['STIG_FILES_DIR']
stig_results_dir = os.environ['STIG_RESULTS_DIR']
stig_zip_file = (f"{working_dir}/{stig_files_dir}/{cyber_dot_mil_stig_name}.zip") ## U_RHEL_9_V2R4_STIG.zip
stig_result_file = (f"{working_dir}/{stig_results_dir}/{cyber_dot_mil_stig_name}_xccdf.xml")
# stig_result_file = "/Users/philgladman/Desktop/home-dir/DevOps/personal/stigs/U_Kubernetes_V2R6_Manual_STIG/U_Kubernetes_STIG_V2R6_Manual-xccdf.xml"
export_ckl_file = (f"{working_dir}/{stig_results_dir}/{cyber_dot_mil_stig_name}_{formatted_date}_post_python_script.ckl")

# Check if it exists (file or directory)
if os.path.exists(stig_zip_file):
    print(f"Path exists: {stig_zip_file}")
else:
    print(f"Path does not exist: {stig_zip_file}")
    exit(1)

if os.path.exists(stig_result_file):
    print(f"Path exists: {stig_result_file}")
else:
    print(f"Path does not exist: {stig_result_file}")
    exit(1)


def convert_xml_file_to_dict(filename):
    with open(filename, "r") as f:
        read_file = f.read()

    return xmltodict.parse(read_file)

def get_hostname(dictonary):
    asset_info = dictonary['cdf:Benchmark']['cdf:TestResult']['cdf:target-facts']['cdf:fact']
    for fact in asset_info:
        if "host_name" in fact['@name']:
            host_name = fact['#text']
            print(f"host_name: {host_name}")

            return host_name

def get_stig_id(dictonary):
    rear_matter = dictonary['cdf:Benchmark']['cdf:rear-matter']
    for line in rear_matter.splitlines():
        key, separator, value = line.partition(":--:")
        if separator and key == "stigid":
            return value

    raise ValueError("Unable to find stigid in XCCDF rear-matter")

def create_stig_results_dict(dictonary):
    rule_results = dictonary['cdf:Benchmark']['cdf:TestResult']['cdf:rule-result']
    rule_results_dict = []
    for rule in rule_results:
        id_ref = rule['@idref'].split("_", 3)[3]
        status = rule['cdf:result']
        if status == "fail":
            status = "Open"
        elif status == "notapplicable":
            status = "Not_Applicable"
        elif status == "pass":
            status = "NotAFinding"
        elif status == "error":
            status = "Not_Reviewed"
        elif status == "notchecked":
            status = "Not_Reviewed"
        else:
            print("ERROR: Status not found")
        rule_dict = {"rule_id": id_ref, "status": status}
        rule_results_dict.append(rule_dict)

    return rule_results_dict

def overwrite_stig_id(stig_info, stig_id):
    for stig_data in stig_info:
        if stig_data.findtext("SID_NAME") == "stigid":
            old_stig_id = stig_data.findtext("SID_DATA")
            stig_data.find("SID_DATA").text = stig_id
            print(f"Overwriting stigid: {old_stig_id} to {stig_id}")
            return

    raise ValueError("Unable to find stigid in generated checklist")

def overwrite_stig_status(results, base):
    for rule in results:
        result_rule_id = rule["rule_id"]
        result_rule_status = rule["status"]
        base_stig_status = ""
        for base_stig_data in base:
            base_stig_rule_id = base_stig_data[3][1].text
            if base_stig_rule_id == result_rule_id:
                print("#"*50)
                if base_stig_data.tag == "VULN":
                    for vuln in base_stig_data:
                        if vuln.tag == "STATUS":
                            base_stig_status = vuln.text
                            vuln.text = result_rule_status
                            print(f"Overwriting rule: {base_stig_rule_id} from {base_stig_status} to {result_rule_status}")

## Convert xccdf.xml scan results file into python dict so can be parsed
xml_dict = convert_xml_file_to_dict(stig_result_file)

## Get hostname from xccdf.xml scan results file
host_name = get_hostname(xml_dict)

## Get STIG ID from xccdf.xml scan results file
stig_id = get_stig_id(xml_dict)

## Define additional mandatory Checklist info, needed for generat_ckl function
checklist_info ={
  "ROLE": "None",
  "ASSET_TYPE": "Computing",
  "MARKING": "CUI",
  "HOST_NAME": host_name,
  "HOST_IP": "127.0.0.1",
  "HOST_MAC": "",
  "HOST_FQDN": host_name,
  "TARGET_COMMENT": "",
  "TECH_AREA": "",
  "TARGET_KEY": "3425",
  "WEB_OR_DATABASE": "false",
  "WEB_DB_SITE": "",
  "WEB_DB_INSTANCE": ""
}

## Generate CKL XML OBJECT
raw_ckl = generate_ckl(stig_zip_file, checklist_info)

## Save new checklist to a .ckl file
generate_ckl_file(raw_ckl, export_ckl_file)

## Create dictonary from xccdf.xml scan results file that contains only rule ids and status
rule_results_dict = create_stig_results_dict(xml_dict)

## Read and parse base checklist .ckl file
tree = ET.ElementTree(file=export_ckl_file)
root = tree.getroot()

## Overwrite STIG ID with the value from xccdf.xml
overwrite_stig_id(root.find("./STIGS/iSTIG/STIG_INFO"), stig_id)

## Overwrite status of base checklist .ckl file with results from xccdf.xml
overwrite_stig_status(rule_results_dict, root[1][0])

## Write/save updated .ckl to file
ET.indent(tree, space="\t")
tree.write(export_ckl_file, encoding='UTF-8', xml_declaration=True, short_empty_elements=False)
