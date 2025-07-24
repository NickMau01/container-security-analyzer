import subprocess
import json
import os
import shutil
import csv
import pandas as pd
from contextlib import redirect_stdout, redirect_stderr
from collections import defaultdict

def get_output_dir(image_name, tool_name):
    """
    Generate output directory path based on image name and tool name (Trivy or Grype).
    """
    sanitized_image_name = image_name.replace("/", "_").replace(":", "_")
    return os.path.join("outputs", "scanner_reports", sanitized_image_name, tool_name)

# Extract all unique vulnerability field names from a Trivy report
def extract_vuln_fields(data):
    fields = set()
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            fields.update(vuln.keys())
    return fields

# Print per-field, per-CVE missingness
def report_missing_details(data, fields, vuln_count):
    missing_map = { f: [] for f in fields }
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln.get("VulnerabilityID", "<UNKNOWN>")
            for f in fields:
                if f not in vuln:
                    missing_map[f].append(vid)
    for f, vids in missing_map.items():
        if len(vids) == vuln_count:
            print(f"  • {f}: missing in all {vuln_count} vulnerabilities")
        else:
            print(f"  • {f}: missing in {len(vids)}/{vuln_count} CVEs")

def get_missing_fields_by_cve(data):
    """
    Returns:
        - complete_count: number of CVEs with all expected fields
        - total_count: total number of CVEs
        - missing_map: dict of {CVE_ID: set of missing fields}
    """
    all_fields = extract_vuln_fields(data)
    missing_map = {}
    complete_count = 0
    total = 0

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            total += 1
            vid = vuln.get("VulnerabilityID", "<UNKNOWN>")
            missing = all_fields - set(vuln.keys())
            if not missing:
                complete_count += 1
            else:
                if vid not in missing_map:
                    missing_map[vid] = missing

    return complete_count, total, missing_map

def report_missing_by_vuln(data):
    """
    - Print how many vulnerabilities have all possible fields (complete entries).
    - Then list those that are missing at least one field, sorted by descending number of missing fields.
    """
    union = extract_vuln_fields(data)
    total = 0
    complete_count = 0
    missing_details = []

    # Count total and collect missing-field info per vulnerability
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            total += 1
            vid = vuln.get("VulnerabilityID", "<UNKNOWN>")
            missing = union - set(vuln.keys())
            if not missing:
                complete_count += 1
            else:
                missing_details.append((vid, missing))

    # Summary line: how many are fully populated
    print(f"{complete_count}/{total} vulnerabilities have all {len(union)} fields")

    if missing_details:
        # Sort vulnerabilities by number of missing fields (descending)
        missing_details.sort(key=lambda x: len(x[1]), reverse=True)
        print("Per-vulnerability missing fields:")
        for vid, missing in missing_details:
            print(f"  • {vid}: missing {len(missing)} fields: {', '.join(sorted(missing))}")

# Perform a Trivy vulnerability scan on a Docker image
def scan_docker_image(image_name, output_dir, fields_file="scanner/expected_fields.json"):
    if not shutil.which("trivy"):
        print("Error: Trivy is not installed or is not in PATH")
        return None

    # Creating output directory
    os.makedirs(output_dir, exist_ok=True)

    # Create subdirectory for this image
    image_folder_name = image_name.replace("/", "_").replace(":", "_")

    # Dynamically create log file based on image name
    log_file = os.path.join(output_dir, f"log_scan_report_{image_folder_name}_trivy.txt")

    data = None
    with open(log_file, "w", encoding="utf-8") as log:
        with redirect_stdout(log), redirect_stderr(log):
            print(f"Scanning Docker image: {image_name}")

            # Construct output file name
            output_file = os.path.join(output_dir, f"{image_folder_name}_trivy.json")
            
            # Runs the Trivy command to scan the image into JSON format and save the result to file
            result = subprocess.run([
                "trivy", "image",
                "--format", "json",
                "--output", output_file,
                image_name
            ], capture_output=True, text=True)

            # Check if Trivy returned an error
            if result.returncode != 0:
                print("Trivy scan failed:\n", result.stderr)
                return None
            else:
                print(f"Vulnerability report saved to {output_file}")
            
            # Try to upload the JSON file to parse its contents
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"Error reading/parsing JSON file: {e}")
                return None
            
            # Calculate the total vulnerabilities by adding them in all the "Results"
            vuln_count = sum(len(r.get("Vulnerabilities", [])) for r in data.get("Results", []))
            print(f"Total vulnerabilities found: {vuln_count}")

            # If there are no vulnerabilities, skip further analysis
            if vuln_count == 0:
                return data
            
            # Extract actual vulnerability fields from this report
            actual_fields = extract_vuln_fields(data)

            # Load the set of expected fields from disk (if it exists)
            if os.path.exists(fields_file):
                with open(fields_file) as ef:
                    expected = set(json.load(ef))
            else:
                expected = set()

            # Append any brand-new fields to the expected list and save
            new_fields = actual_fields - expected
            if new_fields:
                print(f"New fields in {image_name}: {new_fields}")
                expected |= new_fields
                with open(fields_file, "w") as ef:
                    json.dump(sorted(expected), ef, indent=2)
            
            # Show which expected fields are missing in this report
            missing_fields = expected - actual_fields
            if missing_fields:
                print(f"Missing expected fields in {image_name}:")
                report_missing_details(data, missing_fields, vuln_count)

            # Print the per-vulnerability completeness report
            report_missing_by_vuln(data)

    # Returns the full contents of the JSON for future use
    return data

# Convert Trivy report into a pandas DataFrame, ordered by severity and CVSS score
def prepare_vulnerability_dataframe(data):
    findings = []
    image_name = data.get("ArtifactName", "unknown")
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            # extract CVSS score handling both dict (Trivy) and string (merged) formats
            raw_cvss = vuln.get("CVSS", "")
            if isinstance(raw_cvss, dict):
                cvss_score = raw_cvss.get("nvd", {}).get("V3Score", "")
            else:
                cvss_score = raw_cvss

            findings.append({
                "VulnerabilityID": vuln.get("VulnerabilityID", ""),
                "PkgName": vuln.get("PkgName", ""),
                "InstalledVersion": vuln.get("InstalledVersion", ""),
                "Severity": vuln.get("Severity", ""),
                "FixedVersion": vuln.get("FixedVersion", "-"),
                "CVSS": cvss_score
            })

    if not findings:
        print("No vulnerabilities found.")
        return None, image_name

    df = pd.DataFrame(findings)

    # Order vulnerabilities by severity, then by descending CVSS score
    severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}
    df["SeverityRank"] = df["Severity"].str.upper().map(severity_order).fillna(6)
    df["CVSS_Score"] = pd.to_numeric(df["CVSS"], errors="coerce").fillna(-1)
    df.sort_values(["SeverityRank", "CVSS_Score"], ascending=[True, False], inplace=True)
    df.drop(columns=["SeverityRank", "CVSS_Score"], inplace=True)

    return df, image_name

# Export report to Markdown format, both flat and grouped by package
def save_markdown_report(df, image_name, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    flat_name = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_flat_trivy.md")
    grouped_name = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_by_package_trivy.md")
    
    severity_counts = df["Severity"].str.upper().value_counts().to_dict()
    total = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total} " + "(" + ", ".join([f"{k.capitalize()}: {v}" for k, v in sorted(severity_counts.items(), key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].index(x[0]))]) + ")"

    empty_fields = (
        df.isna().sum().sum() +
        (df == "").sum().sum() +
        (df == "-").sum().sum()
    )

    # Flat report
    with open(flat_name, "w", encoding="utf-8") as f:
        f.write(f"# Vulnerability Report for `{image_name}` (Flat View)\n\n")
        f.write(summary_line + "\n\n")
        f.write(f"- Empty fields: **{empty_fields}**\n\n")
        f.write(df.to_markdown(index=False))
    
    # Grouped report
    with open(grouped_name, "w", encoding="utf-8") as f:
        f.write(f"# Vulnerability Report for `{image_name}` (Grouped by Package)\n\n")
        f.write(summary_line + "\n\n")
        f.write(f"- Empty fields: **{empty_fields}**\n\n")
        for pkg in df["PkgName"].unique():
            subset = df[df["PkgName"] == pkg]
            f.write(f"## Package: `{pkg}`\n\n")
            f.write(subset.drop(columns=["PkgName"]).to_markdown(index=False))
            f.write("\n\n")
    
    print(f"Markdown reports saved to {flat_name} and {grouped_name}")

# Save DataFrame to CSV
def save_csv_report(df, image_name, output_dir, scanner_name):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_flat_{scanner_name}.csv")
    df.to_csv(csv_path, index=False)
    print(f"CSV report saved to {csv_path}")

# Generate a report on how many CVEs affect multiple packages
def report_cve_package_distribution(data, output_dir="outputs/scanner_reports", image_name="report"):
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_cve_package_distribution_trivy.md")

    # Build CVE-to-package mapping
    cve_map = defaultdict(set)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            if cve and pkg:
                cve_map[cve].add(pkg)

    # Split CVEs into multi-package and single-package
    multi_pkg_cves = {cve: pkgs for cve, pkgs in cve_map.items() if len(pkgs) > 1}
    single_pkg_cves = {cve for cve, pkgs in cve_map.items() if len(pkgs) == 1}

    # Prepare DataFrame for summary table
    df_summary = pd.DataFrame(
        sorted(
            [(cve, len(pkgs)) for cve, pkgs in multi_pkg_cves.items()],
            key=lambda x: x[1],
            reverse=True
        ),
        columns=["CVE ID", "# Packages"]
    )

    # Get the count of complete CVEs (with all expected fields), total CVEs, and a map of missing fields per CVE
    complete, total, missing_map = get_missing_fields_by_cve(data)

    # Count how many CVEs with missing fields are in each category
    multi_with_missing  = len([cve for cve in multi_pkg_cves if cve in missing_map])
    single_with_missing = len([cve for cve in single_pkg_cves if cve in missing_map])
    unique_with_missing = len(missing_map)

    # Helper function to compute a percentage string with 1 decimal place
    def percent(part, whole):
        return f"{(100 * part / whole):.1f}%" if whole else "0.0%"

    # Create a summary table with total CVEs and how many are missing fields, categorized by package count
    summary_rows = [
        {
        "Category": "Total unique CVEs", 
        "Count": len(cve_map), 
        "With missing fields": len(missing_map), 
        "Percentage with missing fields": percent(unique_with_missing, len(cve_map))
        },
        {
        "Category": "CVEs affecting more than one package", 
        "Count": len(multi_pkg_cves), 
        "With missing fields": multi_with_missing, 
        "Percentage with missing fields": percent(multi_with_missing, len(multi_pkg_cves))
        },
        {
        "Category": "CVEs affecting only one package", 
        "Count": len(single_pkg_cves), 
        "With missing fields": single_with_missing, 
        "Percentage with missing fields": percent(single_with_missing, len(single_pkg_cves))
        },
    ]

    # Convert summary to a DataFrame for Markdown rendering
    df_summary_table = pd.DataFrame(summary_rows)

    # Build a map of missing fields per CVE per package to detect inconsistencies
    inconsistent_cves = defaultdict(dict)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            if not cve or not pkg:
                continue
            # Identify which expected fields are missing for this (CVE, package) entry
            missing = set(m for m in missing_map.get(cve, set()) if m not in vuln)
            inconsistent_cves[cve][pkg] = missing
    
    # Select CVEs that appear in multiple packages and have differing sets of missing fields (inconsistencies)
    warnings = {
        cve: pkgs for cve, pkgs in inconsistent_cves.items()
        if len(pkgs) > 1 and len({frozenset(v) for v in pkgs.values()}) > 1
    }

    # Write Markdown report
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# CVE-to-Package Report for `{image_name}`\n\n")

        f.write("## Summary\n")
        f.write(f"- CVEs with all expected fields: **{complete} / {total}** → **{total - complete}** have missing fields\n\n")
        f.write(df_summary_table.to_markdown(index=False))
        f.write("\n\n---\n\n")

        # Prepare lists to store multi- and single-package CVE details
        multi_rows = []
        single_rows = []
        field_details = defaultdict(list)

        # Build rows for CVEs affecting multiple packages, including how many packages and missing fields
        for cve, pkgs in multi_pkg_cves.items():
            n_missing = len(missing_map.get(cve, set()))
            multi_rows.append({
                "CVE ID": cve,
                "# Packages": len(pkgs),
                "# Missing Fields": n_missing
            })
            if cve in missing_map:
                field_details[cve] = sorted(missing_map[cve])

        # Same as above, but for single-package CVEs
        for cve in single_pkg_cves:
            n_missing = len(missing_map.get(cve, set()))
            single_rows.append({
                "CVE ID": cve,
                "# Missing Fields": n_missing
            })
            if cve in missing_map:
                field_details[cve] = sorted(missing_map[cve])

        # Create DataFrames and sort by missing fields in descending order
        df_multi = pd.DataFrame(multi_rows).sort_values(by="# Missing Fields", ascending=False)
        df_single = pd.DataFrame(single_rows).sort_values(by="# Missing Fields", ascending=False)

        # Write multi-package CVEs section to Markdown
        f.write("## CVEs affecting multiple packages\n\n")
        f.write(df_multi.to_markdown(index=False))
        f.write("\n\n")

        # Write single-package CVEs section to Markdown
        f.write("## CVEs affecting only one package\n\n")
        f.write(df_single.to_markdown(index=False))
        f.write("\n\n")

        # Write the list of missing fields for each single-package CVE (sorted by number of missing fields)
        if field_details:
            f.write("## Missing Fields (Single-package CVEs)\n\n")
            sorted_items = sorted(
                ((cve, sorted(missing_map[cve])) for cve in single_pkg_cves if cve in missing_map),
                key=lambda item: len(item[1]),
                reverse=True
            )
            for cve, fields in sorted_items:
                f.write(f"- **{cve}**: {', '.join(fields)}\n")
            f.write("\n")

        # Write the detailed list of packages per CVE (only for multi-package CVEs), including missing field notes
        f.write("## Detailed package list per CVE\n\n")
        for cve, pkgs in sorted(multi_pkg_cves.items(), key=lambda x: len(x[1]), reverse=True):
            pkg_list = ", ".join(sorted(pkgs))
            f.write(f"- **{cve}** → {len(pkgs)} packages\n  `{pkg_list}`\n")
            if cve in missing_map:
                # Add note if missing fields are inconsistent across package
                note = " ([WARNING] inconsistent across packages — see warning section)" if cve in warnings else ""
                f.write(f"  Missing fields: {', '.join(sorted(missing_map[cve]))}{note}\n")
            f.write("\n")
        
        # Write the warning section for inconsistent missing fields across packages
        if warnings:
            f.write("## Warnings: Inconsistent Missing Fields\n\n")
            for cve, pkg_map in sorted(warnings.items()):
                f.write(f"- **{cve}**\n")
                for pkg, fields in sorted(pkg_map.items()):
                    f.write(f"  - `{pkg}`: {sorted(fields)}\n")
                f.write("\n")

    print(f"Report saved to: {report_path}")

def run_grype_scan(image_name, output_dir):
    """
    Run a Grype vulnerability scan on the given Docker image.
    Saves the JSON output in the same directory as Trivy reports.
    Returns the parsed JSON dictionary or None on failure.
    """
    grype_output_file = os.path.join(
        output_dir, image_name.replace("/", "_").replace(":", "_") + "_grype.json"
    )
    print(f"Running Grype scan for: {image_name}")

    # Execute the Grype command
    result = subprocess.run([
        "grype", image_name,
        "--output", "json",
        "--file", grype_output_file
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Grype scan failed:\n{result.stderr}")
        return None

    print(f"Grype report saved to: {grype_output_file}")

    try:
        with open(grype_output_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to parse Grype JSON: {e}")
        return None

# Convert Grype JSON scan results into a pandas DataFrame
def prepare_grype_dataframe(grype_data):
    findings = []

    # Extract the Docker image name from the Grype report
    source = grype_data.get("source", {})
    target = source.get("target", {})
    image_name = target.get("userInput", "unknown") if isinstance(target, dict) else "unknown"

    # Parse each vulnerability match
    for match in grype_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vuln.get("fix", {})
        cvss_list = vuln.get("cvss", [])

        findings.append({
            "VulnerabilityID": vuln.get("id", ""),
            "PkgName": artifact.get("name", ""),
            "InstalledVersion": artifact.get("version", ""),
            "Severity": vuln.get("severity", ""),
            "FixedVersion": fix.get("versions", ["-"])[0] if fix.get("versions") else "-",
            "CVSS": cvss_list[0].get("metrics", {}).get("baseScore", "") if cvss_list else ""
        })

    if not findings:
        print("[Grype] No vulnerabilities found.")
        return None, image_name

    df = pd.DataFrame(findings)

    # Rank vulnerabilities by severity and CVSS
    severity_order = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "NEGLIGIBLE": 5,
        "UNKNOWN": 6,
        "INFO": 7,
        "UNDEFINED": 8
    }
    df["SeverityRank"] = df["Severity"].str.upper().map(severity_order).fillna(9)
    df["CVSS_Score"] = pd.to_numeric(df["CVSS"], errors="coerce").fillna(-1)
    df.sort_values(["SeverityRank", "CVSS_Score"], ascending=[True, False], inplace=True)
    df.drop(columns=["SeverityRank", "CVSS_Score"], inplace=True)

    return df, image_name

# Save the Grype vulnerability report to Markdown format
def save_grype_markdown_report(df, image_name, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    flat_name = os.path.join(output_dir, f"{image_name}_flat_grype.md")
    grouped_name = os.path.join(output_dir, f"{image_name}_by_package_grype.md")

    severity_counts = df["Severity"].str.upper().value_counts().to_dict()
    total = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total} " + "(" + ", ".join([
        f"{k.capitalize()}: {v}" for k, v in sorted(
            severity_counts.items(),
            key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE','UNKNOWN','INFO','UNDEFINED'].index(x[0])
        )
    ]) + ")"

    empty_fields = (
        df.isna().sum().sum() +
        (df == "").sum().sum() +
        (df == "-").sum().sum()
    )

    # Flat report
    with open(flat_name, "w", encoding="utf-8") as f:
        f.write(f"# Grype Vulnerability Report for `{image_name}` (Flat View)\n\n")
        f.write(summary_line + "\n\n")
        f.write(f"- Empty fields: **{empty_fields}**\n\n")
        f.write(df.to_markdown(index=False))

    # Grouped-by-package report
    with open(grouped_name, "w", encoding="utf-8") as f:
        f.write(f"# Grype Vulnerability Report for `{image_name}` (Grouped by Package)\n\n")
        f.write(summary_line + "\n\n")
        f.write(f"- Empty fields: **{empty_fields}**\n\n")
        for pkg in df["PkgName"].unique():
            subset = df[df["PkgName"] == pkg]
            f.write(f"## Package: `{pkg}`\n\n")
            f.write(subset.drop(columns=["PkgName"]).to_markdown(index=False))
            f.write("\n\n")

    print(f"[Grype] Markdown reports saved to:\n  - {flat_name}\n  - {grouped_name}")

# Generate a Markdown report on CVEs affecting multiple packages (Grype scan)
def report_grype_cve_package_distribution(grype_data, output_dir="outputs/scanner_reports", image_name="report"):
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{image_name}_cve_package_distribution_grype.md")

    cve_map = defaultdict(set)

    for match in grype_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cve = vuln.get("id")
        pkg = artifact.get("name")
        if cve and pkg:
            cve_map[cve].add(pkg)

    multi_pkg_cves = {cve: pkgs for cve, pkgs in cve_map.items() if len(pkgs) > 1}
    single_pkg_cves = {cve for cve, pkgs in cve_map.items() if len(pkgs) == 1}

    df_summary = pd.DataFrame(
        sorted(
            [(cve, len(pkgs)) for cve, pkgs in multi_pkg_cves.items()],
            key=lambda x: x[1],
            reverse=True
        ),
        columns=["CVE ID", "# Packages"]
    )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Grype CVE-to-Package Report for `{image_name}`\n\n")

        f.write("## Summary\n")
        f.write(f"- Total unique CVEs: **{len(cve_map)}**\n")
        f.write(f"- CVEs affecting more than one package: **{len(multi_pkg_cves)}**\n")
        f.write(f"- CVEs affecting only one package: **{len(single_pkg_cves)}**\n\n")
        f.write("---\n\n")

        f.write("## CVEs affecting multiple packages (summary table)\n\n")
        f.write(df_summary.to_markdown(index=False))
        f.write("\n\n---\n\n")

        f.write("## Detailed package list per CVE\n\n")
        for cve, pkgs in sorted(multi_pkg_cves.items(), key=lambda x: len(x[1]), reverse=True):
            pkg_list = ", ".join(sorted(pkgs))
            f.write(f"- **{cve}** → {len(pkgs)} packages\n  `{pkg_list}`\n\n")

    print(f"[Grype] CVE-package distribution report saved to: {report_path}")

def compare_cve_sets(trivy_data, grype_data, image_name, output_dir="outputs/comparisons"):
    """
    Compare the set of CVEs detected by Trivy and Grype.
    Save the difference.
    """
    os.makedirs(output_dir, exist_ok=True)
    trivy_cves = set()
    grype_cves = set()

    # Extract Trivy CVEs
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln.get("VulnerabilityID")
            if vid:
                trivy_cves.add(vid)

    # Extract Grype CVEs
    for match in grype_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        vid = vuln.get("id")
        if vid:
            grype_cves.add(vid)

    # Compare
    common = trivy_cves & grype_cves
    only_trivy = trivy_cves - grype_cves
    only_grype = grype_cves - trivy_cves

    # Write to file
    report_file = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_cve_comparison.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# CVE Comparison Report for `{image_name}`\n\n")
        f.write(f"- Total CVEs in Trivy: **{len(trivy_cves)}**\n")
        f.write(f"- Total CVEs in Grype: **{len(grype_cves)}**\n")
        f.write(f"- CVEs in both: **{len(common)}**\n")
        f.write(f"- CVEs only in Trivy: **{len(only_trivy)}**\n")
        f.write(f"- CVEs only in Grype: **{len(only_grype)}**\n\n")

        if only_trivy:
            f.write("## CVEs only in Trivy\n")
            for cve in sorted(only_trivy):
                f.write(f"- {cve}\n")
            f.write("\n")

        if only_grype:
            f.write("## CVEs only in Grype\n")
            for cve in sorted(only_grype):
                f.write(f"- {cve}\n")

    print(f" CVE comparison report saved to: {report_file}")

def prepare_merged_dataframe(data):
    """
    Convert merged JSON (Trivy-like) into a DataFrame, including 'Sources' field.
    """
    findings = []
    image_name = data.get("ArtifactName", "unknown")
    for res in data.get("Results", []):
        for vuln in res.get("Vulnerabilities", []):
            raw_cvss = vuln.get("CVSS", "")
            if isinstance(raw_cvss, dict):
                cvss_score = raw_cvss.get("nvd", {}).get("V3Score", "")
            else:
                cvss_score = raw_cvss

            findings.append({
                "VulnerabilityID":       vuln.get("VulnerabilityID", ""),
                "PkgName":               vuln.get("PkgName", ""),
                "InstalledVersion":      vuln.get("InstalledVersion", ""),
                "Severity":              vuln.get("Severity", ""),
                "FixedVersion":          vuln.get("FixedVersion", "-"),
                "CVSS":                  cvss_score,
                "Source":                ";".join(vuln.get("Sources", []))
            })

    if not findings:
        print("[Merged] No vulnerabilities to report.")
        return None, image_name

    df = pd.DataFrame(findings)

    severity_order = {"CRITICAL":1, "HIGH":2, "MEDIUM":3, "LOW":4, "UNKNOWN":5}
    df["SeverityRank"] = df["Severity"].str.upper().map(severity_order).fillna(6)
    df["CVSS_Score"]   = pd.to_numeric(df["CVSS"], errors="coerce").fillna(-1)
    df.sort_values(["SeverityRank","CVSS_Score"], ascending=[True,False], inplace=True)
    df.drop(columns=["SeverityRank","CVSS_Score"], inplace=True)

    return df, image_name

def report_extra_occurrences(trivy_data, grype_data, tool_name, output_path):
    """
    Generate CSV of CVEs already in Trivy with extra packages found by Grype.
    """
    # Collect all CVE from Trivy package
    trivy_map = defaultdict(set)
    for r in trivy_data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            trivy_map[v["VulnerabilityID"]].add(v["PkgName"])
    # For each Grype match, if the CVE is already there but the package is not, it goes in extra
    extras = []
    for m in grype_data.get("matches", []):
        cve = m["vulnerability"]["id"]
        pkg = m["artifact"]["name"]
        if cve in trivy_map and pkg not in trivy_map[cve]:
            extras.append((cve, pkg))
    
    # Let's make sure the destination directory exists
    output_dir = os.path.dirname(output_path)
    os.makedirs(output_dir, exist_ok=True)
    
    # Write CSV
    with open(output_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE", "Pacchetto extra", "Trovato da"])
        for cve, pkg in extras:
            writer.writerow([cve, pkg, tool_name])
    print(f"Extra occurrences report: {output_path}")

def merge_trivy_grype(trivy_data, grype_data):
    """
    Combine Trivy and Grype findings into a single Python dict:

    - Each Trivy finding appears once, with Sources=["Trivy"].
    - Grype-only findings are added once, with Sources=["Grype"].
    - Duplicate Grype matches (same CVE+package) are preserved separately, also Sources=["Grype"].
    - Common findings get Sources=["Trivy","Grype"], filling in any missing FixedVersion or CVSS from Grype's metadata.
    - FixedVersion is taken from the Grype vulnerability's 'fix.versions' list (if available), otherwise remains "-".

    Returns:
        dict: A Python dict in the same structure as a Trivy JSON report,
              containing all merged vulnerabilities under ["Results"][0]["Vulnerabilities"].
    """
    merged = {}
    duplicates = []
    grype_seen = defaultdict(int)

    # Loading all unique Trivy entries
    for res in trivy_data.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            key = (v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"])
            entry = v.copy()
            entry["Sources"] = ["Trivy"]
            merged[key] = entry
            grype_seen[key] = 0

    # Scroll through all occurrences of Grype
    for m in grype_data.get("matches", []):
        v_g = m["vulnerability"]
        art = m.get("artifact", {})
        cve = v_g["id"]
        pkg = art.get("name", "unknown")
        installed = art.get("version", "")

        # Extract FixedVersion: first m_fix if valid, otherwise first v_g_fix
        m_fix = m.get("fix", {}).get("version")
        if m_fix and m_fix != "-":
            fix = m_fix
        else:
            vg_versions = v_g.get("fix", {}).get("versions") or []
            fix = vg_versions[0] if vg_versions else "-"

        # estrai CVSS
        cvss = next(
            (f.get("score")
             for f in v_g.get("metadata", {}).get("cvss", [])
             if f.get("score")),
            None
        )
        key = (cve, pkg, installed)

        if grype_seen[key] == 0:
            # FIRST Grype occurrence for this key
            if key in merged:
                # Common: update Sources and fill in missing fields
                orig = merged[key]
                if "Grype" not in orig["Sources"]:
                    orig["Sources"].append("Grype")
                if (not orig.get("FixedVersion") or orig["FixedVersion"] == "-") and fix != "-":
                    orig["FixedVersion"] = fix
                if (not orig.get("CVSS")) and cvss:
                    orig["CVSS"] = cvss
            else:
                # ONLY Grype, first occurrence
                merged[key] = {
                    "VulnerabilityID":   cve,
                    "PkgName":           pkg,
                    "InstalledVersion":  installed,
                    "Severity":          v_g.get("severity", ""),
                    "FixedVersion":      fix,
                    "CVSS":              cvss,
                    "Sources":           ["Grype"]
                }
        else:
            # DUPLICATE Grype: save with all fields
            duplicates.append({
                "VulnerabilityID":   cve,
                "PkgName":           pkg,
                "InstalledVersion":  installed,
                "Severity":          v_g.get("severity", ""),
                "FixedVersion":      fix,
                "CVSS":              cvss,
                "Sources":           ["Grype"]
            })

        grype_seen[key] += 1

    # Combine unique and duplicates
    merged_list = list(merged.values()) + duplicates

    return {
        "ArtifactName": trivy_data.get("ArtifactName", "unknown"),
        "Results": [
            {"Target": "Merged", "Vulnerabilities": merged_list}
        ]
    }

def save_merged_markdown_report(df, image_name, output_dir):
    """
    Export the merged DataFrame to two Markdown files:
    - flat view
    - grouped-by-package view
    """
    os.makedirs(output_dir, exist_ok=True)
    safe_name = image_name.replace("/", "_").replace(":", "_")
    flat_md = os.path.join(output_dir, f"{safe_name}_flat_merged.md")
    grouped_md = os.path.join(output_dir, f"{safe_name}_by_package_merged.md")

    # summary line
    severity_counts = df["Severity"].str.upper().value_counts().to_dict()
    total = sum(severity_counts.values())
    order = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
    summary = (
        f"Total vulnerabilities: {total} "
        f"(" + ", ".join(
            f"{k.capitalize()}: {severity_counts.get(k,0)}"
            for k in order if k in severity_counts
        ) + ")"
    )

    empty_fields = (
        df.isna().sum().sum() +
        (df == "").sum().sum() +
        (df == "-").sum().sum()
    )

    # Flat Report
    with open(flat_md, "w", encoding="utf-8") as f:
        f.write(f"# Merged Vulnerability Report for `{image_name}` (Flat View)\n\n")
        f.write(summary + "\n\n")
        f.write(f"- Empty fields: **{empty_fields}**\n\n")
        f.write(df.to_markdown(index=False))

    # Grouped Report
    with open(grouped_md, "w", encoding="utf-8") as f:
        f.write(f"# Merged Vulnerability Report for `{image_name}` (Grouped by Package)\n\n")
        f.write(summary + "\n\n")
        f.write(f"- Empty fields: **{empty_fields}**\n\n")
        for pkg in df["PkgName"].unique():
            subset = df[df["PkgName"] == pkg]
            f.write(f"## Package: `{pkg}`\n\n")
            f.write(subset.drop(columns=["PkgName"]).to_markdown(index=False))
            f.write("\n\n")

    print(f"[Merged] Markdown reports saved to:\n  - {flat_md}\n  - {grouped_md}")

def report_discrepancies_csv(trivy_df: pd.DataFrame,
                             grype_df: pd.DataFrame,
                             output_csv: str):
    """
    Compare the Severity, FixedVersion and CVSS fields of common CVEs
    (same VulnerabilityID, PkgName, InstalledVersion),
    and save a CSV with all discrepancies.
    """
    # Merge on 3 key fields
    common = trivy_df.merge(
        grype_df,
        on=["VulnerabilityID", "PkgName", "InstalledVersion"],
        how="inner",
        suffixes=("_trivy", "_grype")
    )

    # Fields to compare
    fields = ["Severity", "FixedVersion", "CVSS"]
    rows = []

    for field in fields:
        tcol = field + "_trivy"
        gcol = field + "_grype"
        # Select only rows where both values ​​exist and are different
        diff = common[
            # Both non-null
            common[tcol].notna() & common[gcol].notna() &
            # Both non-empty string
            (common[tcol] != "")   & (common[gcol] != "")   &
            # Both not "-" placeholder
            (common[tcol] != "-")  & (common[gcol] != "-")  &
            # and different values
            (common[tcol] != common[gcol])
        ]
        # for Severity, ignore case-only differences
        if field == "Severity":
            diff = diff[diff[f"{tcol}"].str.lower() != diff[f"{gcol}"].str.lower()]

        for _, r in diff.iterrows():
            rows.append({
                "VulnerabilityID":   r["VulnerabilityID"],
                "PkgName":           r["PkgName"],
                "InstalledVersion":  r["InstalledVersion"],
                "Field":             field,
                "TrivyValue":        r[tcol],
                "GrypeValue":        r[gcol],
            })

    # Save the CSV
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    pd.DataFrame(rows).to_csv(output_csv, index=False)
    print(f"Discrepancies CSV saved in: {output_csv}")

def report_discrepancies_md(trivy_df: pd.DataFrame,
                            grype_df: pd.DataFrame,
                            image_name: str,
                            output_md: str):
    """
    Like report_discrepancies_csv, but writes a REPORT in Markdown.
    """
    common = trivy_df.merge(
        grype_df,
        on=["VulnerabilityID", "PkgName", "InstalledVersion"],
        how="inner",
        suffixes=("_trivy", "_grype")
    )

    fields = ["Severity", "FixedVersion", "CVSS"]
    rows = []
    for field in fields:
        tcol = field + "_trivy"
        gcol = field + "_grype"
        diff = common[
            # Both non-null
            common[tcol].notna() & common[gcol].notna() &
            # Both non-empty string
            (common[tcol] != "")   & (common[gcol] != "")   &
            # Both not "-" placeholder
            (common[tcol] != "-")  & (common[gcol] != "-")  &
            # and different values
            (common[tcol] != common[gcol])
        ]
        if field == "Severity":
            diff = diff[diff[f"{tcol}"].str.lower() != diff[f"{gcol}"].str.lower()]
        for _, r in diff.iterrows():
            rows.append((r["VulnerabilityID"],
                         r["PkgName"],
                         r["InstalledVersion"],
                         field,
                         str(r[tcol]),
                         str(r[gcol])))

    # Compose the Markdown
    total = len(rows)
    per_field = {f: sum(1 for row in rows if row[3] == f) for f in fields}
    summary = f"Total discrepancies: **{total}**  \n" + \
              " | ".join(f"{f}: {per_field[f]}" for f in fields if per_field[f] > 0)

    cols = ["VulnerabilityID","PkgName","InstalledVersion","Field","Trivy Value","Grype Value"]
    # Width calculation
    widths = {col: len(col) for col in cols}
    for r in rows:
        for i, cell in enumerate(r):
            widths[cols[i]] = max(widths[cols[i]], len(cell))

    # Header and separator
    header    = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"
    separator = "|-" + "-|-".join("-"*widths[c] for c in cols) + "-|"
    lines = [header, separator]

    # Body
    for r in rows:
        line = "| " + " | ".join(r[i].ljust(widths[cols[i]]) for i in range(len(cols))) + " |"
        lines.append(line)

    md = [
        f"# Discrepancy Report for `{image_name}`",
        "",
        summary,
        "",
        *lines
    ]

    os.makedirs(os.path.dirname(output_md), exist_ok=True)
    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"Discrepancies Markdown saved in: {output_md}")

def report_improvements(orig_df, merged_df, fields, tool_name, image_name, output_md):
    """
    Compare orig_df and merged_df for the given fields across all common CVE+PkgName+InstalledVersion entries.
    Generate a Markdown table that shows how many missing fields in only-{tool_name} were filled in the merged results.
    Also list the CVEs with fields that were originally missing.
    """
    # Inner join on VulnerabilityID, PkgName, and InstalledVersion
    common = orig_df.merge(
        merged_df,
        on=["VulnerabilityID", "PkgName", "InstalledVersion"],
        how="inner",
        suffixes=("", "_merged")
    )

    # Prepare rows for the summary table
    rows = []
    for f in fields:
        orig_col   = f
        merged_col = f + "_merged"
        # Identify originally missing entries in orig_df
        missing    = common[orig_col].isna() | (common[orig_col] == "") | (common[orig_col] == "-")
        # Identify entries filled in merged_df that were missing before
        filled     = common[merged_col].notna() & (common[merged_col] != "") & (common[merged_col] != "-")
        tot_miss   = int(missing.sum())
        tot_fill   = int((missing & filled).sum())
        # Compute improvement percentage
        pct        = f"{tot_fill/ tot_miss*100:.1f}%" if tot_miss>0 else "N/A"
        rows.append({
            "Field":               f,
            f"Missing in only–{tool_name}": tot_miss,
            "Filled in merged":    tot_fill,
            "Improvement %":       pct
        })

    # Calculate column widths for Markdown formatting
    cols   = list(rows[0].keys()) if rows else []
    widths = {c: len(c) for c in cols}
    for r in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(r[c])))

    # Construct Markdown table header, separator, and body
    header    = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"
    separator = "|-" + "-|-".join("-" * widths[c] for c in cols) + "-|"
    body      = [
        "| " + " | ".join(str(r[c]).ljust(widths[c]) for c in cols) + " |"
        for r in rows
    ]

    # Markdown content
    md = [
        f"# Improvement Report: {tool_name} → Merged for `{image_name}`",
        "",
        f"This table shows how many missing fields in only–{tool_name} were filled in the merged report:\n",
        header, separator,
        *body,
        ""
    ]

    # Identify and list CVEs that had missing fields in the original only–tool report
    missing_details = defaultdict(list)
    for idx, row in common.iterrows():
        vid = row["VulnerabilityID"]
        pkg = row["PkgName"]
        # Determine which fields were missing originally
        mfields = [f for f in fields if pd.isna(row[f]) or row[f] == "" or row[f] == "-"]
        if mfields:
            missing_details[(vid, pkg)] = mfields
    
    if missing_details:
        md.append("## CVEs con campi mancanti in only–{tool_name}")
        for (vid, pkg), mfields in missing_details.items():
            md.append(f"- **{vid}** (`{pkg}`): {', '.join(mfields)}")
        md.append("")

    # Write the Markdown content to the output file
    os.makedirs(os.path.dirname(output_md), exist_ok=True)
    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"Improvement report saved in: {output_md}")

if __name__ == "__main__":
    image = "vulnerables/web-dvwa"
    image_folder = os.path.join("outputs/scanner_reports", image.replace("/", "_").replace(":", "_"))

    # Generate paths for each scanner
    trivy_output_dir = get_output_dir(image, "Trivy")
    grype_output_dir = get_output_dir(image, "Grype")

    # Trivy
    trivy_data = scan_docker_image(image,trivy_output_dir)
    if trivy_data:
        df_trivy, image_name = prepare_vulnerability_dataframe(trivy_data)
        if df_trivy is not None:
            save_markdown_report(df_trivy, image_name, output_dir=trivy_output_dir)
            save_csv_report(df_trivy, image_name, trivy_output_dir,"trivy")
            report_cve_package_distribution(trivy_data, output_dir=trivy_output_dir, image_name=image_name)
    
    # Grype
    grype_data = run_grype_scan(image, grype_output_dir)
    if grype_data:
        df_grype, grype_image_name = prepare_grype_dataframe(grype_data)
        if df_grype is not None:
            sanitized_grype_image_name = grype_image_name.replace("/", "_").replace(":", "_")
            save_grype_markdown_report(df_grype, sanitized_grype_image_name, output_dir=grype_output_dir)
            save_csv_report(df_grype, sanitized_grype_image_name, grype_output_dir, "grype")
            report_grype_cve_package_distribution(grype_data, output_dir=grype_output_dir, image_name=sanitized_grype_image_name)
    
    # Compare Trivy vs Grype CVEs
    if trivy_data and grype_data:
        report_extra_occurrences(trivy_data, grype_data, "Grype",
                             os.path.join(get_output_dir(image, "extras"),
                                          f"{image}_extra_occurrences.csv"))
        compare_cve_sets(trivy_data, grype_data, image)
    
    merged = merge_trivy_grype(trivy_data, grype_data)
    df_merged, _ = prepare_merged_dataframe(merged)
    
    save_csv_report(df_merged, image, get_output_dir(image, "merged"), "merged")
    save_merged_markdown_report(
        df_merged,
        image,
        get_output_dir(image, "merged")
    )
    
    csv_path = os.path.join(get_output_dir(image, "merged"),
                            f"{image.replace('/', '_')}_field_discrepancies.csv")
    md_path  = os.path.join(get_output_dir(image, "merged"),
                            f"{image.replace('/', '_')}_field_discrepancies.md")

    report_discrepancies_csv(df_trivy, df_grype, csv_path)
    report_discrepancies_md (df_trivy, df_grype, image, md_path)

    merged_dir = get_output_dir(image, "merged")

    report_improvements(
        orig_df=   df_trivy,
        merged_df=df_merged,
        fields=[ "FixedVersion", "CVSS" ],
        tool_name="Trivy",
        image_name=image,
        output_md=os.path.join(
            merged_dir,
            f"{image.replace('/', '_')}_improvement_trivy.md"
        )
    )

    report_improvements(
        orig_df=   df_grype,
        merged_df=df_merged,
        fields=[ "FixedVersion", "CVSS" ],
        tool_name="Grype",
        image_name=image,
        output_md=os.path.join(
            merged_dir,
            f"{image.replace('/', '_')}_improvement_grype.md"
        )
    )
    