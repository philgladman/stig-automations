# stig-automations
Repository to automate stig scanning and stig checklist file creation

## Notes
sudo yum install oscap scap-security-content
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results results.xml --report report.html ssg-ubuntu2004-ds-1.2.xml
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_common --stig-viewer test.ckl /home/pgladman/test-oscap/U_RHEL_9_V2R3_Manual_STIG/U_RHEL_9_STIG_V2R3_Manual-xccdf.xml

oscap xccdf eval --stig-viewer test.ckl /home/pgladman/test-oscap/U_RHEL_9_V2R3_Manual_STIG/U_RHEL_9_STIG_V2R3_Manual-xccdf.xml
oscap xccdf eval --stig-viewer test.ckl /home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml

oscap info "/home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml"
oscap xccdf generate guide /home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml > test.html
oscap xccdf eval --report test-2.html /home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml

Manual xccdf file
- /home/pgladman/test-oscap/U_RHEL_9_V2R3_Manual_STIG/U_RHEL_9_STIG_V2R3_Manual-xccdf.xml
SCAP Benchmark
- /home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark-updated.xml
## Working, then create checklist in stig viewer. Then overlay the `test-xccdf.xml` file to create the final checklist
oscap xccdf eval --report test.html --stig-viewer test.ckl --results test-xccdf.xml /home/pgladman/test-oscap/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark-updated.xml


#### Notes
- Install scap-security-guide opensc
sudo yum install -y scap-security-guide openscap wget unzip git
mkdir oscap-stigs
cd oscap-stigs
- Install SCAP Content
wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.zip
unzip U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.zip
- Install Manual STIG for base .xml
wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R3_STIG.zip
unzip U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.zip
- Remove CPE form xml file so RHEL9 will run against AL2023
<!-- line_start=$(grep -n "platform-specification" U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml | head -n 1 | cut -d ":" -f 1)
line_end=$(grep -n "platform-specification" U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml | tail -n 1 | cut -d ":" -f 1)
sed -i "${line_start},${line_end}d" U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml  -->
line_cpe=$(grep -n "xccdf:platform idref=\"cpe:/o:redhat:enterprise_linux:9.0\" />" U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml | tail -n 1 | cut -d ":" -f 1)
sed -i "${line_cpe}d" U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml 
- Run oscap to scan local machine with the 
oscap xccdf eval --report test.html --stig-viewer test.ckl --results test-xccdf.xml U_RHEL_9_V2R3_STIG_SCAP_1-3_Benchmark.xml
- Clone stig automations repo
git clone https://github.com/philgladman/stig-automations.git
cd stig-automations
- Install python module stig_parser
sudo python3 -m ensurepip
sudo pip3 install -r requirements.txt
- Run python script to create a base/empty checklist file
At this point will have a xccdf.xml file that contains all the scan results from oscap. And will have a base/empty checklist file.
  - xccdf.xml
  - checklist.ckl
  - Update variables in script - soon to be env vars
- run python script to overlay results from `xccdf.xml` to `checklist.ckl`
sudo python3 stig-automations/stig_combined.py
scp /home/ec2-user/oscap-stigs/U_RHEL_9_V2R3_STIG_Mar_27_2025_142924.ckl
scp /home/pgladman/U_RHEL_9_V2R3_STIG_Mar_27_2025_142924.ckl
- Run stig-checklist-overrides.sh bash script to override false positives