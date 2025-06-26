import subprocess
import json
import os
from contextlib import redirect_stdout, redirect_stderr

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

def scan_docker_image(image_name, output_dir = "outputs/scanner_reports", fields_file="scanner/expected_fields.json"):
    print(f"Scanning Docker image: {image_name}")

    # Creating output directory
    os.makedirs(output_dir, exist_ok=True)

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

if __name__ == "__main__":
    # Open a log file and redirect both stdout and stderr
    with open("outputs/scanner_reports/scan_report.txt", "w", encoding="utf-8") as log:
        with redirect_stdout(log), redirect_stderr(log):
            scan_docker_image("vulnerables/web-dvwa")