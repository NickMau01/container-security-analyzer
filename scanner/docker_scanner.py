import subprocess
import json
import os
import shutil
import csv
import pandas as pd
from pathlib import Path
from collections import defaultdict

def create_output_dir(safe_name, tool_name):
    """
    Create (if needed) and return the output directory path based on a sanitized image
    name (safe_name) and the scanner name (tool_name, e.g., "Trivy" or "Grype").
    """
    path = os.path.join("outputs", "scanner_reports", safe_name, tool_name)
    os.makedirs(path, exist_ok=True)
    return path

# Extract all unique vulnerability field names from a report
def extract_fields(data, tool_name):
    """
    Extract the set of unique vulnerability-related field names from a scanner report.

    Args:
    data (dict): Parsed JSON report produced by the scanner.
    tool_name (str): "trivy" or "grype".

    Returns:
    set[str]: Unique field names found across vulnerabilities.

    Raises:
    ValueError: If the scanner name is unknown.
    """
    fields = set()
    if tool_name == "trivy":
        # Trivy JSON shape: Results[*].Vulnerabilities[*]
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                fields.update(vuln.keys())
    elif tool_name == "grype":
        # Grype JSON shape: matches[*] with nested vulnerability and artifact
        for match in data.get("matches", []):
            fields.update(match.get("vulnerability", {}).keys())
            fields.update(match.get("artifact", {}).keys())
    else:
        raise ValueError(f"Unknown scanner '{tool_name.capitalize()}': cannot extract vulnerability data")
    return fields

# Print per-field, per-CVE missingness
def report_missing_details(data, fields, vuln_count, tool_name):
    """
    Print, for each expected field, how many CVEs are missing that field.

    Args:
    data (dict): Parsed scanner JSON.
    fields (Iterable[str]): Fields to check.
    vuln_count (int): Total number of vulnerability records considered.
    tool_name (str): "trivy" or "grype".
    """
    missing_map = { f: [] for f in fields }
    if tool_name == "trivy":
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                vid = vuln.get("VulnerabilityID", "<UNKNOWN>")
                for f in fields:
                    if f not in vuln:
                        missing_map[f].append(vid)
    elif tool_name == "grype":
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            art  = match.get("artifact", {})
            vid = vuln.get("id", "<UNKNOWN>")
            for f in fields:
                if f not in vuln and f not in art:
                    missing_map[f].append(vid)
    for f, vids in missing_map.items():
        if len(vids) == vuln_count:
            print(f"  • {f}: missing in all {vuln_count} vulnerabilities")
        else:
            print(f"  • {f}: missing in {len(vids)}/{vuln_count} CVEs")

def run_scan(tool_name, image_name, cmd_args, fields_file):
    """
    Run a scanner command, load its JSON output, update expected fields, and
    print a short per-field missingness summary.

    Flow:
    1) Execute the scanner CLI with the provided arguments.
    2) Load the JSON report from the output file (Trivy: --output, Grype: --file).
    3) Update the expected_fields JSON file with any newly observed fields.
    4) Print missing-field statistics per expected field.

    Returns:
    dict | None: Parsed JSON data on success, or None on error.
    """
    if not shutil.which(tool_name):
        print(f"Error: {tool_name} is not installed or is not in PATH")
        return None

    print(f"[{tool_name.capitalize()}] Running scan for: {image_name}")
    result = subprocess.run(cmd_args, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[{tool_name.capitalize()}] Scan failed:\n", result.stderr)
        return None
    
    # Determine the output file flag based on the tool (Trivy: --output; Grype: --file)
    if tool_name == "trivy":
        output_file = cmd_args[cmd_args.index("--output")+1]
    elif tool_name == "grype":
        output_file = cmd_args[cmd_args.index("--file")+1]
    else:
        raise ValueError(f"Cannot determine JSON output file for tool '{tool_name.capitalize()}'")

    out = Path(output_file)
    if not out.is_file() or out.stat().st_size == 0:
        raise RuntimeError(f"File missing or empty: {out}")

    print(f"[{tool_name.capitalize()}] JSON report saved to: {output_file}")

    try:
        with open(output_file, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to parse {tool_name.capitalize()} JSON: {e}")
        return None

    # Count vulnerability records
    if tool_name == "trivy":
        vuln_count = sum(len(r.get("Vulnerabilities", [])) for r in data.get("Results", []))
    elif tool_name == "grype":
        vuln_count = len(data.get("matches", []))
    else:
        raise ValueError(f"Unknown scanner '{tool_name.capitalize()}': cannot extract vulnerability data")

    if vuln_count == 0:
        print(f"[{tool_name.capitalize()}] No vulnerabilities found in {image_name}.")
        return data
    
    actual_fields = extract_fields(data, tool_name)

    # Update expected_fields file
    if os.path.exists(fields_file):
        with open(fields_file) as ef:
            expected = set(json.load(ef))
    else:
        expected = set()

    new_fields = actual_fields - expected
    if new_fields:
        print(f"[{tool_name.capitalize()}] New fields found in {image_name}: {sorted(new_fields)}")
        expected |= new_fields
        with open(fields_file, "w") as ef:
            json.dump(sorted(expected), ef, indent=2)

    # Print missing fields summary
    missing_fields = expected - actual_fields
    if missing_fields and vuln_count:
        print(f"[{tool_name.capitalize()}] Missing expected fields in {image_name}:")
        
        report_missing_details(data, missing_fields, vuln_count, tool_name)

    return data

def prepare_dataframe(data, tool_name):
    """
    Convert a Trivy/Grype/Merged JSON dict into a normalized DataFrame ready for reporting.
    - Normalizes to columns: VulnerabilityID, PkgName, InstalledVersion, Severity, FixedVersion, CVSS
    - Ranks by severity (tool-specific order) then by CVSS (desc) for stable presentation
    - For Grype/Merged only: flags per-key duplicates (same CVE, package, installed version) via
        a 'Duplicates' column set to 'X' for the second and subsequent occurrences.
    Returns:
        pandas.DataFrame | None: normalized DataFrame; None if no findings.
    """
    findings = []
    if tool_name in ("trivy", "merged"): 
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                raw_cvss = v.get("CVSS", "")
                if isinstance(raw_cvss, dict):
                    cvss_score = raw_cvss.get("nvd", {}).get("V3Score", "")
                else:
                    cvss_score = raw_cvss
                record = {
                    "VulnerabilityID": v.get("VulnerabilityID",""),
                    "PkgName":         v.get("PkgName",""),
                    "InstalledVersion":v.get("InstalledVersion",""),
                    "Severity":        v.get("Severity",""),
                    "FixedVersion":    v.get("FixedVersion","-"),
                    "CVSS":            cvss_score
                }
                if tool_name == "merged":
                    record["Source"] = ";".join(v.get("Sources", []))
                findings.append(record)
    elif tool_name == "grype":
        for m in data.get("matches", []):
            v = m.get("vulnerability", {})
            a = m.get("artifact", {})
            fix = m.get("fix",{})        
            vg_versions = v.get("fix", {}).get("versions", [])
            fixed_version = fix.get("version") or (vg_versions[0] if vg_versions else "-")
            cvss_entries = v.get("cvss", [])
            nvd_scores = [
                c["metrics"]["baseScore"]
                for c in cvss_entries
                if "nvd" in c.get("source", "").lower() and c.get("version") == "3.1"
            ]
            score = nvd_scores[0] if nvd_scores else ""
            findings.append({
                "VulnerabilityID": v.get("id",""),
                "PkgName":         a.get("name",""),
                "InstalledVersion":a.get("version",""),
                "Severity":        v.get("severity",""),
                "FixedVersion":    fixed_version,
                "CVSS":            score
            })
    if not findings:
        print(f"[{tool_name.capitalize()}] No vulnerabilities found.")
        return None

    df = pd.DataFrame(findings)
    order = ({"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}
             if tool_name=="trivy"
             else {"CRITICAL":1,"HIGH":2,"MEDIUM":3,"LOW":4,"NEGLIGIBLE":5,"UNKNOWN":6,"INFO":7,"UNDEFINED":8})
    df["SeverityRank"] = df["Severity"].str.upper().map(order).fillna(9)
    df["CVSS_Score"] = pd.to_numeric(df["CVSS"], errors="coerce").fillna(-1)
    df.sort_values(["SeverityRank","CVSS_Score"], ascending=[True,False], inplace=True)
    if tool_name in ("grype", "merged"):
        key_cols = ["VulnerabilityID", "PkgName", "InstalledVersion"]
        dup_mask = df.duplicated(subset=key_cols, keep="first")
        df["Duplicates"] = dup_mask.map({True: "X", False: ""})
    return df.drop(columns=["SeverityRank","CVSS_Score"])

def save_markdown_report(df, image_name, safe_name, output_dir, tool_name):
    """
    Write two Markdown reports for a scanner:
    - Flat view: single table of all findings
    - Grouped-by-package view
    Notes on duplicates:
    - For Grype/Merged, the 'Duplicates' column is included (if present in df) and
      two summary lines are printed in both views:
        'Non-duplicates: ...' and 'Duplicates: ...' (with severity breakdown).
    - For Trivy, duplicates are not relevant and no extra lines are rendered.
    """
    flat_name = os.path.join(output_dir, f"{safe_name}_flat_{tool_name}.md")
    grouped_name = os.path.join(output_dir, f"{safe_name}_by_package_{tool_name}.md")
    
    df = df.copy()
    with_dups = tool_name in ("grype", "merged")

    if with_dups:
        # Recompute duplicate mask here to guarantee consistency with the final ordering
        key_cols = ["VulnerabilityID", "PkgName", "InstalledVersion"]
        dup_mask = df.duplicated(subset=key_cols, keep="first")
        df["Duplicates"] = dup_mask.map({True: "X", False: ""})

    severity_counts = df["Severity"].str.upper().value_counts().to_dict()
    total = sum(severity_counts.values())
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN", "INFO", "UNDEFINED"]

    summary = (
        f"Total vulnerabilities: {total} (" +
        ", ".join(f"{level.capitalize()}: {severity_counts[level]}"
                for level in severity_order if level in severity_counts) +
        ")"
    )

    def _sev_summary_line(subdf, label):
        """
        Format a one-line severity summary for a subset (used for Non-duplicates / Duplicates),
        rendered as "Label: total (Critical: x, High: y, ...)" using severity_order.
        """
        counts = subdf["Severity"].str.upper().value_counts().to_dict()
        tot = sum(counts.values())
        return (f"{label}: {tot} (" +
                ", ".join(f"{lvl.capitalize()}: {counts[lvl]}"
                          for lvl in severity_order if lvl in counts) +
                ")")

    extra_lines = []
    if with_dups:
        # Compute per-view duplicate summaries for readability
        nondups = df[df["Duplicates"] != "X"]
        dups    = df[df["Duplicates"] == "X"]
        extra_lines = [_sev_summary_line(nondups, "Non-duplicates"),
                       _sev_summary_line(dups, "Duplicates")]

    cols_for_empty = [c for c in df.columns if c != "Duplicates"]
    empty = (df[cols_for_empty].isna().sum().sum()
             + (df[cols_for_empty] == "").sum().sum()
             + (df[cols_for_empty] == "-").sum().sum())

    with open(flat_name, "w", encoding="utf-8") as f:
        f.write(f"# {tool_name.capitalize()} Vulnerability Report for `{image_name}` (Flat View)\n\n")
        f.write(summary+"\n\n")
        # Render duplicate/non-duplicate summaries (only for grype/merged)
        if extra_lines:
            for line in extra_lines:
                f.write(line + "\n")
            f.write("\n")
        f.write(f"- Empty fields: **{empty}**\n\n")
        f.write(df.to_markdown(index=False))

    with open(grouped_name, "w",encoding="utf-8") as f:
        f.write(f"# {tool_name.capitalize()} Vulnerability Report for `{image_name}` (Grouped by Package)\n\n")
        f.write(summary+"\n\n")
        if extra_lines:
            for line in extra_lines:
                f.write(line + "\n")
            f.write("\n")
        f.write(f"- Empty fields: **{empty}**\n\n")
        for pkg in df["PkgName"].unique():
            subset = df[df["PkgName"]==pkg].drop(columns=["PkgName"])
            f.write(f"## Package: `{pkg}`\n\n")
            f.write(f"{subset.to_markdown(index=False)}\n\n")
    
    print(f"[{tool_name.capitalize()}] Markdown reports saved to:\n  - {flat_name}\n  - {grouped_name}")

# Save DataFrame to CSV
def save_csv_report(df, safe_name, output_dir, scanner_name):
    """
    Save a flat CSV report for a given scanner to the output directory.
    For Grype/Merged, the DataFrame may contain the 'Duplicates' column (see prepare_dataframe).
    """
    csv_path = os.path.join(output_dir, f"{safe_name}_flat_{scanner_name}.csv")
    df.to_csv(csv_path, index=False)
    print(f"[{scanner_name.capitalize()}] CSV report saved to: {csv_path}")

def get_missing_fields_by_cve(data, tool_name, expected_fields=None):
    """
    Compute, per CVE, which expected fields are missing.

    Returns a tuple:
    (complete_count, total_count, missing_map)
    where:
    - complete_count is the number of CVEs with all expected fields present,
    - total_count is the total number of CVEs,
    - missing_map is a dict: {CVE_ID -> set[str] of missing fields}.
    """
    missing_map = {}
    complete_count = 0
    total = 0

    if tool_name == "trivy":
        # Determine expected fields on Trivy vulnerabilities
        all_fields = set(expected_fields) if expected_fields else extract_fields(data, tool_name)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                total += 1
                vid = vuln.get("VulnerabilityID", "<UNKNOWN>")
                missing = all_fields - vuln.keys()
                if not missing:
                    complete_count += 1
                else:
                    missing_map.setdefault(vid, missing)

    elif tool_name == "grype":
        # Determine expected fields across Grype vulnerabilities
        if expected_fields:
            all_fields = set(expected_fields)
        else:
            all_fields = set()
            for match in data.get("matches", []):
                all_fields.update(match.get("vulnerability", {}).keys())
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            cve = vuln.get("id")
            if not cve:
                continue
            total += 1
            art = match.get("artifact", {})
            present_keys = set(vuln.keys()) | set(art.keys())
            missing = set(all_fields) - present_keys
            if not missing:
                complete_count += 1
            else:
                missing_map.setdefault(cve, missing)

    else:
        raise ValueError(f"Scanner not supported: {tool_name}")

    return complete_count, total, missing_map

def report_cve_distribution(data, output_dir, image_name, safe_name, get_missing_fn, tool_name):
    """
    Build a CVE→packages report for either Trivy or Grype.

    Steps:
    1) Load expected fields for the scanner (if any) and compute, per CVE,
    which fields are missing.
    2) Build a CVE→package map, also tracking inconsistencies across packages
    for the same CVE.
    3) Produce a Markdown report with:
    - a summary table,
    - per-CVE details for multi- and single-package CVEs, and
    - a section listing missing fields.
    """
    report_path = os.path.join(output_dir, f"{safe_name}_cve_package_distribution_{tool_name}.md")
    # 1) CVE->package mapping
    cve_map = defaultdict(set)
    inconsistent_cves = defaultdict(dict)

    fields_file = f"scanner/expected_fields_{tool_name}.json"
    if os.path.exists(fields_file):
        with open(fields_file) as ef:
            expected_fields = json.load(ef)
    else:
        expected_fields = set()
    
    expected_count = len(expected_fields)

    # 2) Compute completeness and missing-map
    complete, total, missing_map = get_missing_fn(data, tool_name, expected_fields = expected_fields)

    if tool_name == "trivy":
        # Trivy shape
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                cve = vuln.get("VulnerabilityID")
                pkg = vuln.get("PkgName")
                if cve and pkg:
                    cve_map[cve].add(pkg)
                    inconsistent_cves[cve][pkg] = set(m for m in missing_map.get(cve, set()) if m not in vuln)
    elif tool_name == "grype":
        # Grype shape
        for m in data.get("matches", []):
            vuln = m.get("vulnerability", {}) 
            art = m.get("artifact", {})
            cve = vuln.get("id")
            pkg = art.get("name")
            if cve and pkg:
                cve_map[cve].add(pkg)
                expected_missing = missing_map.get(cve, set())
                present = set(vuln.keys()) | set(art.keys())
                incoh = {f for f in expected_missing if f not in present}
                if incoh:
                    inconsistent_cves[cve][pkg] = incoh

    warnings = {
        cve: pkgs for cve, pkgs in inconsistent_cves.items()
        if len(pkgs) > 1 and len({frozenset(v) for v in pkgs.values()}) > 1
    }

    # 3) Split CVEs by number of affected packages
    multi_pkg_cves = {cve:pkgs for cve,pkgs in cve_map.items() if len(pkgs)>1}
    single_pkg_cves = {cve:pkgs for cve,pkgs in cve_map.items() if len(pkgs)==1}

    multi_with_missing  = sum(1 for cve in multi_pkg_cves  if cve in missing_map)
    single_with_missing = sum(1 for cve in single_pkg_cves if cve in missing_map)
    unique_with_missing = len(missing_map)

    def percent(part, total):
        """Return a percentage string with one decimal place."""
        return f"{(100 * part / total):.1f}%" if total else "0.0%"

    # Summary table
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
            "Count":len(single_pkg_cves),
            "With missing fields": single_with_missing,
            "Percentage with missing fields": percent(single_with_missing, len(single_pkg_cves))
        }
    ]
    df_summary_table = pd.DataFrame(summary_rows)

    multi_rows = []
    single_rows = []
    field_details = defaultdict(list)

    for cve, pkgs in multi_pkg_cves.items():
        n_missing = len(missing_map.get(cve, set()))
        multi_rows.append({
            "CVE ID": cve,
            "# Packages": len(pkgs),
            "# Missing Fields": n_missing
        })
        if cve in missing_map:
            field_details[cve] = sorted(missing_map[cve])

    for cve in single_pkg_cves:
        n_missing = len(missing_map.get(cve, set()))
        single_rows.append({
            "CVE ID": cve,
            "# Missing Fields": n_missing
        })
        if cve in missing_map:
            field_details[cve] = sorted(missing_map[cve])
    
    df_multi = pd.DataFrame(multi_rows, columns=["CVE ID", "# Packages", "# Missing Fields"])
    if not df_multi.empty:
        df_multi = df_multi.sort_values(by="# Missing Fields", ascending=False)
    df_single = pd.DataFrame(single_rows, columns=["CVE ID", "# Missing Fields"])
    if not df_single.empty:
        df_single = df_single.sort_values(by="# Missing Fields", ascending=False)

    # Write Markdown
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# {tool_name.capitalize()} CVE-to-Package Report for `{image_name}`\n\n")
        f.write("## Summary\n\n")
        f.write(f"- CVEs with all {expected_count} expected fields: **{complete} / {total}** → **{total - complete}** have missing fields\n\n")
        f.write("### Expected fields\n\n")
        for field in expected_fields:
            f.write(f"- `{field}`\n")
        f.write("\n")
        f.write("## CVEs affecting multiple packages (summary table)\n\n")
        f.write(df_summary_table.to_markdown(index=False))
        f.write("\n\n---\n\n")

        # Multi-package CVEs
        f.write("## CVEs affecting multiple packages\n\n")
        if not df_multi.empty:
            f.write(df_multi.to_markdown(index=False))
        else:
            f.write("No CVEs affecting multiple packages\n")
        f.write("\n\n")

        # Single-package CVEs
        f.write("## CVEs affecting only one package\n\n")
        if not df_single.empty:
            f.write(df_single.to_markdown(index=False))
        else:
            f.write("No CVEs affecting only one package\n")
        f.write("\n\n")

        f.write("## Missing Fields (Single-package CVEs)\n\n")
        if not df_single.empty:
            sorted_items = sorted(
                ((cve, sorted(missing_map[cve])) for cve in single_pkg_cves if cve in missing_map),
                key=lambda item: len(item[1]),
                reverse=True
            )
            for cve, fields in sorted_items:
                f.write(f"- **{cve}**: {', '.join(fields)}\n")
        else:
            f.write("No single-package CVEs found")
        f.write("\n")

        f.write("## Detailed package list per CVE\n\n")
        for cve, pkgs in sorted(multi_pkg_cves.items(), key=lambda x: len(x[1]), reverse=True):
            pkg_list = ", ".join(sorted(pkgs))
            f.write(f"- **{cve}** → {len(pkgs)} packages\n  `{pkg_list}`\n")
            if cve in missing_map:
                note = " ([WARNING] inconsistent across packages — see warning section)" if cve in warnings else ""
                f.write(f"  Missing fields: {', '.join(sorted(missing_map[cve]))}{note}\n")
            f.write("\n")

        if warnings:
            f.write("## Warnings: Inconsistent Missing Fields\n\n")
            for cve, pkg_map in sorted(warnings.items()):
                f.write(f"- **{cve}**\n")
                for pkg, fields in sorted(pkg_map.items()):
                    f.write(f"  - `{pkg}`: {sorted(fields)}\n")
                f.write("\n")

    print(f"[{tool_name.capitalize()}] CVE-package distribution report saved to: {report_path}")

def merge_trivy_grype(trivy_data, grype_data):
    """
    Merge Trivy and Grype findings into a single Trivy-shaped dict.
    Rules:
    - Each unique Trivy finding appears once with Sources=["Trivy"].
    - Each unique Grype finding appears once with Sources=["Grype"].
    - If both scanners have the same (CVE, package, installed version), merge
    them into one entry with Sources=["Trivy", "Grype"]. Fill missing
    FixedVersion (prefer Grype's fix versions) and CVSS (prefer NVD v3.1
    baseScore when present in Grype) if absent in Trivy.
    - Additional Grype matches with the same key are **preserved** as separate
      entries (these become 'Duplicates' later when normalized).
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

    # Iterate over all Grype matches
    for m in grype_data.get("matches", []):
        v_g = m["vulnerability"]
        art = m.get("artifact", {})
        cve = v_g["id"]
        pkg = art.get("name", "unknown")
        installed = art.get("version", "")

        # Extract FixedVersion: prefer the match-level fix.version, else first in vulnerability.fix.versions
        m_fix = m.get("fix", {}).get("version")
        if m_fix and m_fix != "-":
            fix = m_fix
        else:
            vg_versions = v_g.get("fix", {}).get("versions") or []
            fix = vg_versions[0] if vg_versions else "-"

        # Extract CVSS (prefer NVD v3.1 baseScore)
        cvss = None
        cvss_entries = v_g.get("cvss", [])
        for c in cvss_entries:
            score = (c.get("metrics") or {}).get("baseScore")
            if score is None:
                continue
            src = str(c.get("source", "")).lower()
            ver = str(c.get("version", ""))
            if "nvd" in src and ver == "3.1":
                cvss = score
                break

        key = (cve, pkg, installed)

        if grype_seen[key] == 0:
            # FIRST Grype occurrence for this key
            if key in merged:
                # Common entry: update Sources and fill missing fields
                orig = merged[key]
                if "Grype" not in orig["Sources"]:
                    orig["Sources"].append("Grype")
                if (not orig.get("FixedVersion") or orig["FixedVersion"] == "-") and fix != "-":
                    orig["FixedVersion"] = fix
                if (not orig.get("CVSS")) and cvss:
                    orig["CVSS"] = cvss
            else:
                # Grype-only entry
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
            # DUPLICATE Grype occurrence: keep as a separate entry
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

def report_extra_occurrences(trivy_data, grype_data, tool_name, safe_name, merged_dir):
    """
    Generate a CSV listing (CVE, package) pairs that Grype found *in addition to*
    the same CVE already associated with other packages in Trivy.
    """
    # Map CVE -> set of packages from Trivy
    trivy_map = defaultdict(set)
    for r in trivy_data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            trivy_map[v["VulnerabilityID"]].add(v["PkgName"])

    # For each Grype match, if the CVE is already there but the package is not, it goes in extra
    extras = set()
    for m in grype_data.get("matches", []):
        cve = m.get("vulnerability", {}).get("id")
        pkg = m.get("artifact", {}).get("name")
        if not cve or not pkg:
            continue
        pkgs_trivy = trivy_map.get(cve)
        # If the CVE exists in Trivy but this package is new, record it
        if pkgs_trivy and pkg not in pkgs_trivy:
            extras.add((cve, pkg))

    if not extras:
        print(f"[Merged] No extra package occurrences from {tool_name}.")
        return

    csv_path = os.path.join(merged_dir, f"{safe_name}_extra_occurrences.csv")

    # Write CSV
    with open(csv_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE", "Extra Package", "Found by"])
        for cve, pkg in sorted(extras):
            writer.writerow([cve, pkg, tool_name])
    print(f"[Merged] Extra package occurrences report from {tool_name} saved to: {csv_path}")

def compare_cve_sets(trivy_data, grype_data, image_name, safe_name, merged_output_dir):
    """
    Compare the set of CVE IDs detected by Trivy and Grype and write a Markdown summary.

    The report shows totals, overlap, and the CVEs seen only by one scanner.
    """
    trivy_cves = set()
    grype_cves = set()

    # Extract Trivy CVE IDs
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln.get("VulnerabilityID")
            if vid:
                trivy_cves.add(vid)

    # Extract Grype CVE IDs
    for match in grype_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        vid = vuln.get("id")
        if vid:
            grype_cves.add(vid)

    # Compare
    common = trivy_cves & grype_cves
    only_trivy = trivy_cves - grype_cves
    only_grype = grype_cves - trivy_cves

    # Prepare summary data
    df_summary = pd.DataFrame([
        {"Category": "Total CVEs in Trivy", "Count": len(trivy_cves)},
        {"Category": "Total CVEs in Grype", "Count": len(grype_cves)},
        {"Category": "CVEs in both", "Count": len(common)},
        {"Category": "Only in Trivy", "Count": len(only_trivy)},
        {"Category": "Only in Grype", "Count": len(only_grype)}
    ])

    # Write report
    report_file = os.path.join(merged_output_dir, f"{safe_name}_cve_comparison.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# CVE Comparison Report for `{image_name}`\n\n")
        f.write("## Summary\n\n")
        f.write(df_summary.to_markdown(index=False))
        f.write("\n\n")

        if only_trivy:
            f.write("## CVEs only in Trivy\n")
            for cve in sorted(only_trivy):
                f.write(f"- {cve}\n")
            f.write("\n")

        if only_grype:
            f.write("## CVEs only in Grype\n")
            for cve in sorted(only_grype):
                f.write(f"- {cve}\n")

    print(f"[Merged] CVE comparison report saved to: {report_file}")

def report_discrepancies(trivy_df, grype_df, merged_dir, image_name, safe_name):
    """
    Compare the fields Severity, FixedVersion, and CVSS for common entries
    (same VulnerabilityID, PkgName, InstalledVersion) between Trivy and Grype.
    Duplicates handling:
    - Drop rows where Duplicates == 'X' (if present) before the inner join to prevent
      1→N explosions and inflated discrepancy counts.
    Output:
    - Markdown summary (discrepancy counts per field) with a note like:
      'Grype duplicates skipped: **N**'
    - CSV with all discrepancies (one row per actual mismatch).
    """
    output_csv = os.path.join(merged_dir, f"{safe_name}_field_discrepancies.csv")
    output_md  = os.path.join(merged_dir, f"{safe_name}_field_discrepancies.md")

    trivy_df  = trivy_df.copy()
    grype_df  = grype_df.copy()

    skipped = {}
    # Drop per-key duplicate rows reported by Grype (keep first occurrence only)
    if "Duplicates" in grype_df.columns:
        d = int((grype_df["Duplicates"] == "X").sum())
        if d: skipped["Grype"] = d
        grype_df = grype_df[grype_df["Duplicates"] != "X"]

    if "Duplicates" in trivy_df.columns:
        d = int((trivy_df["Duplicates"] == "X").sum())
        if d: skipped["Trivy"] = d
        trivy_df = trivy_df[trivy_df["Duplicates"] != "X"]

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
        if field == "CVSS":
            t = pd.to_numeric(common[tcol], errors="coerce")
            g = pd.to_numeric(common[gcol], errors="coerce")
            diff = common[t.notna() & g.notna() & (t.round(1) != g.round(1))]
        elif field == "Severity":
            diff = common[
                common[tcol].notna() & common[gcol].notna() &
                (common[tcol] != "") & (common[gcol] != "") &
                (common[tcol] != "-") & (common[gcol] != "-") &
                (common[tcol].str.lower() != common[gcol].str.lower())
            ]
        else:
            diff = common[
                common[tcol].notna() & common[gcol].notna() &
                (common[tcol] != "") & (common[gcol] != "") &
                (common[tcol] != "-") & (common[gcol] != "-") &
                (common[tcol] != common[gcol])
            ]

        for _, r in diff.iterrows():
            rows.append({
                "VulnerabilityID":   r["VulnerabilityID"],
                "PkgName":           r["PkgName"],
                "InstalledVersion":  r["InstalledVersion"],
                "Field":             field,
                "TrivyValue":        r[tcol],
                "GrypeValue":        r[gcol],
            })

    df = pd.DataFrame(rows)
    per_field = df["Field"].value_counts().to_dict()
    with open(output_md, "w", encoding="utf-8") as f:
            f.write(f"# Discrepancy Report for `{image_name}`\n\n")
            if skipped:
                line = " | ".join(f"{k} duplicates skipped: **{v}**" for k, v in skipped.items())
                f.write(line + "\n\n")
            f.write(f"Total discrepancies: **{len(rows)}**\n")
            f.write(" | ".join(f"{f}: {per_field[f]}" for f in fields if per_field.get(f, 0) > 0))
            f.write("\n\n")
            f.write(df.to_markdown(index=False))
            f.write("\n\n")

    print(f"[Discrepancies] Markdown saved to: {output_md}")
    # Save the CSV 
    df.to_csv(output_csv, index=False)
    print(f"[Discrepancies] CSV saved to: {output_csv}")

def report_improvements(orig_df, merged_df, fields, tool_name, image_name, merged_dir, safe_name):
    """
    Assess how many missing fields in the original scanner (Trivy/Grype) are
    filled in the merged report, for common (VulnerabilityID, PkgName, InstalledVersion).
    Duplicates handling:
    - Drop rows where Duplicates == 'X' (if present) from both orig_df and merged_df
      before the inner join to avoid 1→N inflation of 'Missing' and 'Filled' counts.
    Output:
    - Markdown table with per-field counts and 'Improvement %', plus a section listing
      CVEs that had missing fields and were improved in merged.
    - A note like 'Merged duplicates skipped: **N**' is printed when applicable.
    """
    output_md = os.path.join(merged_dir, f"{safe_name}_improvement_{tool_name}.md")

    orig_df   = orig_df.copy()
    merged_df = merged_df.copy()
    
    skipped = {}
    if "Duplicates" in orig_df.columns:
        d = int((orig_df["Duplicates"] == "X").sum())
        if d: skipped[tool_name.capitalize()] = d
        orig_df = orig_df[orig_df["Duplicates"] != "X"]

    # Avoid counting the same (CVE, pkg, ver) multiple times in the inner join
    if "Duplicates" in merged_df.columns:
        d = int((merged_df["Duplicates"] == "X").sum())
        if d: skipped["Merged"] = d
        merged_df = merged_df[merged_df["Duplicates"] != "X"]

    # Inner join on VulnerabilityID, PkgName, and InstalledVersion
    common = orig_df.merge(
        merged_df,
        on=["VulnerabilityID", "PkgName", "InstalledVersion"],
        how="inner",
        suffixes=("", "_merged")
    )

    # Build summary rows
    summary_rows = []
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
        summary_rows.append({
            "Field":               f,
            f"Missing in only–{tool_name}": tot_miss,
            "Filled in merged":    tot_fill,
            "Improvement %":       pct
        })

    df_summary = pd.DataFrame(summary_rows)

    # Identify and list CVEs that had missing fields in the original only–tool report
    missing_details = defaultdict(list)
    for idx, row in common.iterrows():
        vid = row["VulnerabilityID"]
        pkg = row["PkgName"]
        ver = row["InstalledVersion"]
        # Determine which fields were missing originally
        mfields = [f for f in fields if pd.isna(row[f]) or row[f] == "" or row[f] == "-"]
        if mfields:
            missing_details[(vid, pkg, ver)] = mfields

    # Write the Markdown content to the output file
    with open(output_md, "w", encoding="utf-8") as f:
        f.write(f"# Improvement Report: {tool_name} → Merged for `{image_name}`\n\n")
        if skipped:
            line = " | ".join(f"{k} duplicates skipped: **{v}**" for k, v in skipped.items())
            f.write(line + "\n\n")
        f.write(f"This table shows how many missing fields in only–{tool_name} were filled in the merged report:\n\n")
        f.write(df_summary.to_markdown(index=False))
        f.write("\n\n")
        if missing_details:
            f.write("---\n\n")
            f.write(f"## CVEs with missing fields in only–{tool_name}\n\n")
            for (vid, pkg, ver), mfields in missing_details.items():
                # Print the CVE and affected package/version
                f.write(f"- **{vid}** (`{pkg}` v{ver})\n")
                # List all fields that were missing in the original report (Trivy or Grype)
                f.write(f"  - Missing fields: {', '.join(mfields)}\n")
                # Check which of those fields were filled in the merged report
                improved_fields = []
                for field in mfields:
                    # Locate the corresponding row in the merged DataFrame
                    merged_val = common.loc[
                        (common["VulnerabilityID"] == vid) &
                        (common["PkgName"] == pkg) &
                        (common["InstalledVersion"] == ver),
                        field + "_merged"
                    ]
                    # If the value exists and is meaningful, consider it an improvement
                    if not merged_val.empty:
                            val = merged_val.values[0]
                            if val and val != "-":
                                improved_fields.append(f"{field} → {val}")
                # If any fields were actually filled, add them to the markdown
                if improved_fields:
                    f.write(f"  - Filled in merged: {', '.join(improved_fields)}\n")
            f.write("\n")

    print(f"[Improvement - {tool_name.capitalize()}] Report saved to: {output_md}")

if __name__ == "__main__":
    image_name = "vulnerables/web-dvwa"
    safe_name = image_name.replace("/", "_").replace(":", "_")

    # Create paths for each scanner
    trivy_output_dir = create_output_dir(safe_name, "Trivy")
    grype_output_dir = create_output_dir(safe_name, "Grype")
    merged_output_dir = create_output_dir(safe_name, "Merged")
    df_trivy = df_grype = df_merged = None

    # Trivy
    trivy_data = run_scan("trivy",
                          image_name,
                          ["trivy","image","--format","json","--output", os.path.join(trivy_output_dir, f"{safe_name}_trivy.json"), image_name],
                          "scanner/expected_fields_trivy.json"
                          )
    if trivy_data:
        df_trivy = prepare_dataframe(trivy_data, "trivy")
        if df_trivy is not None:
            save_markdown_report(df_trivy, image_name, safe_name, trivy_output_dir, "trivy")
            save_csv_report(df_trivy, safe_name, trivy_output_dir,"trivy")
            report_cve_distribution(trivy_data, trivy_output_dir, image_name, safe_name, get_missing_fields_by_cve, "trivy")
        else:
            print("[Trivy] No vulnerabilities to export: Empty DataFrame.")
    else:
        print("[Trivy] No JSON output (scan failed or tool not present). Skipping export and reporting.")

    # Grype
    grype_data = run_scan("grype",
                          image_name,
                          ["grype", image_name, "--output","json","--file", os.path.join(grype_output_dir, f"{safe_name}_grype.json")],
                          "scanner/expected_fields_grype.json"
                          )
    if grype_data:
        df_grype = prepare_dataframe(grype_data, "grype")
        if df_grype is not None:
            save_markdown_report(df_grype, image_name, safe_name, grype_output_dir, "grype")
            save_csv_report(df_grype, safe_name, grype_output_dir, "grype")
            report_cve_distribution(grype_data, grype_output_dir, image_name, safe_name, get_missing_fields_by_cve, "grype")
        else:
            print("[Grype] No vulnerabilities to export: Empty DataFrame.")
    else:
        print("[Grype] No JSON output (scan failed or tool not present). Skipping export and reporting.")

    # Merged
    if trivy_data and grype_data:
        print(f"[Merged] Performing merge and generating merged reports for: {image_name}") 
        merged_data = merge_trivy_grype(trivy_data, grype_data)
        if merged_data:
            df_merged = prepare_dataframe(merged_data,"merged")
            if df_merged is not None:
                save_markdown_report(df_merged, image_name, safe_name, merged_output_dir, "merged")
                save_csv_report(df_merged, safe_name, merged_output_dir, "merged")
            else:
                print("[Merged] No vulnerabilities to export: Empty DataFrame.")
        else:
            print("[Merged] Merge produced no records (no overlap or merge error).")
        
        # Compare Trivy vs Grype CVEs
        report_extra_occurrences(trivy_data, grype_data, "Grype", safe_name, merged_output_dir)
        compare_cve_sets(trivy_data, grype_data, image_name, safe_name, merged_output_dir)
    else:
        if not trivy_data and not grype_data:
            print("[Merged] Merge failed: both Trivy and Grype reports are missing.")
        elif not trivy_data:
            print("[Merged] Merge failed: Trivy report missing.")
        else:
            print("[Merged] Merge failed: Grype report missing.")
        print("[Merged] Skipped Extra & CVE comparison: both Trivy and Grype are needed.")

    if df_trivy is not None and df_grype is not None:
        report_discrepancies(df_trivy, df_grype, merged_output_dir, image_name, safe_name)
    else:
        print("[Merged] Discrepancy report skipped: Trivy/Grype DataFrame not available.")

    if df_trivy is not None and df_merged is not None:
        report_improvements(
            orig_df = df_trivy,
            merged_df = df_merged,
            fields = [ "FixedVersion", "CVSS" ],
            tool_name = "trivy",
            image_name = image_name,
            merged_dir = merged_output_dir,
            safe_name = safe_name
        )
    else:
        print("[Improvement - Trivy] Report failed: need the merged DF and the Trivy one.")

    if df_grype is not None and df_merged is not None:
        report_improvements(
            orig_df = df_grype,
            merged_df = df_merged,
            fields = [ "FixedVersion", "CVSS" ],
            tool_name = "grype",
            image_name = image_name,
            merged_dir = merged_output_dir,
            safe_name = safe_name
        )
    else:
        print("[Improvement - Grype] Report failed: need the merged DF and the Grype one.")
    