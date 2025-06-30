import subprocess
import json
import os
import shutil
import pandas as pd
from contextlib import redirect_stdout, redirect_stderr
from collections import defaultdict

# Extract all unique vulnerability field names from a Trivy report
def extract_vuln_fields(data):
    fields = set()
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            fields.update(vuln.keys())
    return fields

# Print per-field, per-CVE missingness
def report_missing_details(data, fields,vuln_count):
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
def scan_docker_image(image_name, output_dir = "outputs/scanner_reports", fields_file="scanner/expected_fields.json"):
    if not shutil.which("trivy"):
        print("Error: Trivy is not installed or is not in your PATH")
        return None

    # Creating output directory
    os.makedirs(output_dir, exist_ok=True)

    # Create subdirectory for this image
    image_folder_name = image_name.replace("/", "_").replace(":", "_")
    output_dir = os.path.join(output_dir, image_folder_name)
    os.makedirs(output_dir, exist_ok=True)

    # Dynamically create log file based on image name
    log_file = os.path.join(output_dir,f"log_scan_report_{image_name.replace('/', '_').replace(':', '_')}.txt")

    data = None
    with open(log_file, "w", encoding="utf-8") as log:
        with redirect_stdout(log), redirect_stderr(log):
            print(f"Scanning Docker image: {image_name}")

            # Construct output file name
            output_file = os.path.join(output_dir,image_name.replace("/","_").replace(":","_") + ".json")
            
            # Runs the Trivy command to scan the image into JSON format and save the result to file
            result = subprocess.run([
                "trivy", "image",
                "--format", "json",
                "--output", output_file,
                image_name
            ], capture_output=True, text=True)

            # Check if Trivy returned an error
            if result.returncode != 0:
                print(f"Trivy scan failed:\n", result.stderr)
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
                report_missing_details(data, missing_fields,vuln_count)

            # Print the per-vulnerability completeness report
            report_missing_by_vuln(data)

    # Returns the full contents of the JSON for future use
    return data

# Convert Trivy report into a pandas DataFrame, ordered by severity and CVSS
def prepare_vulnerability_dataframe(data):
    findings = []
    image_name = data.get("ArtifactName", "unknown")
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "VulnerabilityID": vuln.get("VulnerabilityID", ""),
                "PkgName": vuln.get("PkgName", ""),
                "InstalledVersion": vuln.get("InstalledVersion", ""),
                "Severity": vuln.get("Severity", ""),
                "FixedVersion": vuln.get("FixedVersion", "-"),
                "CVSS": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", "")
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
    flat_name = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_flat.md")
    grouped_name = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_by_package.md")
    
    severity_counts = df["Severity"].str.upper().value_counts().to_dict()
    total = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total} " + "(" + ", ".join([f"{k.capitalize()}: {v}" for k, v in sorted(severity_counts.items(), key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].index(x[0]))]) + ")"

    # Flat report
    with open(flat_name, "w", encoding="utf-8") as f:
        f.write(f"# Vulnerability Report for `{image_name}` (Flat View)\n\n")
        f.write(summary_line + "\n\n")
        f.write(df.to_markdown(index=False))
    
    # Grouped report
    with open(grouped_name, "w", encoding="utf-8") as f:
        f.write(f"# Vulnerability Report for `{image_name}` (Grouped by Package)\n\n")
        f.write(summary_line + "\n\n")
        for pkg in df["PkgName"].unique():
            subset = df[df["PkgName"] == pkg]
            f.write(f"## Package: `{pkg}`\n\n")
            f.write(subset.drop(columns=["PkgName"]).to_markdown(index=False))
            f.write("\n\n")
    
    print(f"Markdown reports saved to {flat_name} and {grouped_name}")

# Save DataFrame to CSV
def save_csv_report(df, image_name, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_flat.csv")
    df.to_csv(csv_path, index=False)
    print(f"CSV report saved to {csv_path}")

# Generate a report on how many CVEs affect multiple packages
def report_cve_package_distribution(data, output_dir="outputs/scanner_reports", image_name="report"):
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{image_name.replace('/', '_').replace(':', '_')}_cve_package_distribution.md")

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

    # Write Markdown report
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# CVE-to-Package Report for `{image_name}`\n\n")

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
    flat_name = os.path.join(output_dir, f"{image_name}_grype_flat.md")
    grouped_name = os.path.join(output_dir, f"{image_name}_grype_by_package.md")

    severity_counts = df["Severity"].str.upper().value_counts().to_dict()
    total = sum(severity_counts.values())
    summary_line = f"Total vulnerabilities: {total} " + "(" + ", ".join([
        f"{k.capitalize()}: {v}" for k, v in sorted(
            severity_counts.items(),
            key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE','UNKNOWN','INFO','UNDEFINED'].index(x[0])
        )
    ]) + ")"

    # Flat report
    with open(flat_name, "w", encoding="utf-8") as f:
        f.write(f"# Grype Vulnerability Report for `{image_name}` (Flat View)\n\n")
        f.write(summary_line + "\n\n")
        f.write(df.to_markdown(index=False))

    # Grouped-by-package report
    with open(grouped_name, "w", encoding="utf-8") as f:
        f.write(f"# Grype Vulnerability Report for `{image_name}` (Grouped by Package)\n\n")
        f.write(summary_line + "\n\n")
        for pkg in df["PkgName"].unique():
            subset = df[df["PkgName"] == pkg]
            f.write(f"## Package: `{pkg}`\n\n")
            f.write(subset.drop(columns=["PkgName"]).to_markdown(index=False))
            f.write("\n\n")

    print(f"[Grype] Markdown reports saved to:\n  - {flat_name}\n  - {grouped_name}")

# Generate a Markdown report on CVEs affecting multiple packages (Grype scan)
def report_grype_cve_package_distribution(grype_data, output_dir="outputs/scanner_reports", image_name="report"):
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{image_name}_grype_cve_package_distribution.md")

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

if __name__ == "__main__":
    image = "vulnerables/web-dvwa"
    image_folder = os.path.join("outputs/scanner_reports", image.replace("/", "_").replace(":", "_"))

    # Trivy
    trivy_data = scan_docker_image(image)
    if trivy_data:
        df_trivy, image_name = prepare_vulnerability_dataframe(trivy_data)
        if df_trivy is not None:
            image_folder = os.path.join("outputs/scanner_reports", image.replace("/", "_").replace(":", "_"))
            save_markdown_report(df_trivy, image_name, output_dir=image_folder)
            save_csv_report(df_trivy, image_name, output_dir=image_folder)
            report_cve_package_distribution(trivy_data, output_dir=image_folder, image_name=image)
    
    # Grype
    grype_data = run_grype_scan(image, image_folder)
    if grype_data:
        df_grype, grype_image_name = prepare_grype_dataframe(grype_data)
        if df_grype is not None:
            sanitized_grype_image_name = grype_image_name.replace("/", "_").replace(":", "_")
            save_grype_markdown_report(df_grype, sanitized_grype_image_name, output_dir=image_folder)
            save_csv_report(df_grype, sanitized_grype_image_name + "_grype", output_dir=image_folder)
            report_grype_cve_package_distribution(grype_data, output_dir=image_folder, image_name=sanitized_grype_image_name)