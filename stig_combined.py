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
import xmltodict
import json
from stig_parser import convert_xccdf, generate_ckl, generate_ckl_file
from datetime import datetime
import xml.etree.ElementTree as ET


formatted_date = datetime.now().strftime("%b_%d_%Y_%H%M%S")
working_dir = "/Users/phillipgladman/Desktop/DevOps/tcode/oscap-tests"
cyber_dot_mil_stig_name = "U_RHEL_9_V2R3_STIG"
stig_zip_file = (f"{working_dir}/{cyber_dot_mil_stig_name}.zip")
stig_result_file = (f"{working_dir}/test-xccdf.xml")
export_ckl_file = (f"{working_dir}/{cyber_dot_mil_stig_name}_{formatted_date}.ckl")

def convert_xml_file_to_dict(filename):
    with open(filename, "r") as f:
        read_file = f.read()

    return xmltodict.parse(read_file)

def get_hostname(dictonary):
    asset_info = dictonary['Benchmark']['TestResult']['target-facts']['fact']
    for fact in asset_info:
        if "urn:xccdf:fact:asset:identifier:host_name" in fact['@name']:
            host_name = fact['#text']
            # print(f"host_name: {host_name}")

            return host_name

def create_stig_results_dict(dictonary):
    rule_results = dictonary['Benchmark']['TestResult']['rule-result']
    rule_results_dict = []
    for rule in rule_results:
        id_ref = rule['@idref'].split("_", 3)[3]
        status = rule['result']
        if status == "fail":
            status = "Open"
        elif status == "notapplicable":
            status = "Not_Applicable"
        elif status == "pass":
            status = "NotAFinding"
        elif status == "error":
            status = "Not_Reviewed"
        else:
            print("ERROR: Status not found")
        rule_dict = {"rule_id": id_ref, "status": status}
        rule_results_dict.append(rule_dict)

    return rule_results_dict

def overwite_stig_status(results, base):
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

## Define additional mandatory Checklist info, needed for generat_ckl function
checklist_info ={
  "ROLE": "None",
  "ASSET_TYPE": "Computing",
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

## Overwrite status of base checklist .ckl file with results from xccdf.xm
overwite_stig_status(rule_results_dict, root[1][0])

## Write/save updated .ckl to file
tree.write(export_ckl_file, encoding='utf-8')