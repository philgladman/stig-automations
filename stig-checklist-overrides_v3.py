#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


STATUS_MAP = {
    "Fail": "Open",
    "NA": "Not_Applicable",
    "Pass": "NotAFinding",
}


def get_required_env(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required environment variable is not set: {name}")
    return value


def resolve_path(working_dir, path):
    path = Path(path)
    if path.is_absolute():
        return path
    return working_dir / path


def find_input_ckl(results_dir, stig_name):
    configured_path = os.environ.get("STIG_CKL_FILE")
    if configured_path:
        return resolve_path(results_dir, configured_path)

    matching_files = list(results_dir.glob(f"{stig_name}_*_post_python_script.ckl"))
    if not matching_files:
        raise FileNotFoundError(
            f"Unable to find generated CKL matching "
            f"{results_dir}/{stig_name}_*_post_python_script.ckl"
        )

    return max(matching_files, key=lambda path: path.stat().st_mtime)


def get_output_ckl(input_ckl):
    configured_path = os.environ.get("STIG_OVERRIDE_OUTPUT_FILE")
    if configured_path:
        return resolve_path(input_ckl.parent, configured_path)

    output_name = input_ckl.name.replace(
        "_post_python_script.ckl", "_post_python_overrides.ckl"
    )
    if output_name == input_ckl.name:
        output_name = f"{input_ckl.stem}_post_python_overrides.ckl"

    return input_ckl.with_name(output_name)


def load_overrides(overrides_dir):
    override_files = sorted(overrides_dir.glob("*.json"))
    if not override_files:
        raise FileNotFoundError(f"No JSON override files found in {overrides_dir}")

    overrides = {}
    for override_file in override_files:
        with override_file.open() as file:
            override_data = json.load(file)

        for check in override_data.get("stig_checks", []):
            check_id = check["check_id"]
            if check_id in overrides:
                raise ValueError(f"Duplicate override found for {check_id}")
            if check["status"] not in STATUS_MAP:
                raise ValueError(
                    f"Unsupported status for {check_id}: {check['status']}"
                )
            overrides[check_id] = check

    return overrides


def get_rule_version(vuln):
    for stig_data in vuln.findall("STIG_DATA"):
        if stig_data.findtext("VULN_ATTRIBUTE") == "Rule_Ver":
            return stig_data.findtext("ATTRIBUTE_DATA")
    return None


def apply_overrides(tree, overrides, engineer, allow_missing):
    vulns_by_rule_version = {}
    for vuln in tree.getroot().findall("./STIGS/iSTIG/VULN"):
        rule_version = get_rule_version(vuln)
        if rule_version:
            if rule_version in vulns_by_rule_version:
                raise ValueError(f"Duplicate Rule_Ver found in checklist: {rule_version}")
            vulns_by_rule_version[rule_version] = vuln

    missing_ids = sorted(set(overrides) - set(vulns_by_rule_version))
    if missing_ids and not allow_missing:
        raise ValueError(
            "Override IDs not found in checklist: " + ", ".join(missing_ids)
        )
    if missing_ids:
        print(
            "WARNING: Skipping override IDs not found in checklist: "
            + ", ".join(missing_ids),
            file=sys.stderr,
        )

    todays_date = datetime.now().strftime("%m-%d-%Y")
    applied_count = 0
    for check_id, override in overrides.items():
        vuln = vulns_by_rule_version.get(check_id)
        if vuln is None:
            continue
        status = STATUS_MAP[override["status"]]
        comments = (
            f"{override['status']} - {todays_date}-{engineer} - "
            f"evidence: {override['comment']}"
        )
        vuln.find("STATUS").text = status
        vuln.find("COMMENTS").text = comments
        print(f"Overwriting {check_id}: status={status}")
        applied_count += 1

    return applied_count


def main():
    working_dir = Path(get_required_env("STIG_WORKING_DIR"))
    results_dir = resolve_path(working_dir, get_required_env("STIG_RESULTS_DIR"))
    stig_name = get_required_env("STIG_CYBER_MIL_NAME")
    overrides_dir = resolve_path(working_dir, get_required_env("STIG_OVERRIDES_DIR"))
    engineer = os.environ.get("STIG_OVERRIDE_ENGINEER", "rap_pipeline")
    allow_missing = os.environ.get("STIG_ALLOW_MISSING_OVERRIDES", "").lower() == "true"

    input_ckl = find_input_ckl(results_dir, stig_name)
    output_ckl = get_output_ckl(input_ckl)
    overrides = load_overrides(overrides_dir)

    if not input_ckl.exists():
        raise FileNotFoundError(f"Checklist does not exist: {input_ckl}")

    tree = ET.parse(input_ckl)
    applied_count = apply_overrides(tree, overrides, engineer, allow_missing)
    ET.indent(tree, space="\t")
    tree.write(
        output_ckl,
        encoding="UTF-8",
        xml_declaration=True,
        short_empty_elements=False,
    )
    print(f"Applied {applied_count} overrides")
    print(f"Created checklist: {output_ckl}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)