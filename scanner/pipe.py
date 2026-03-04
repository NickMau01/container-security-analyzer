import os
from pathlib import Path

from fetcher import docker_fetcher as fetcher
from scanner import docker_scanner as scanner

def run_pipeline(image_name):
    """Run the end-to-end pipeline:
    - Fetch the image as a Docker archive (pull + save)
    - Scan the saved archive with Trivy and Grype
    - Generate per-tool and merged reports
    - Compare CVE sets and produce discrepancy/improvement reports
    """
    safe_name = image_name.replace("/", "_").replace(":", "_")

    # 1) Fetch: pull + docker save
    fetched = fetcher.fetch_image(image_name)  # returns { "image_tar": ..., "extracted_dir": ... }
    tar_path = Path(fetched["image_tar"])
    print(f"[Pipeline] Docker archive: {tar_path}")

    trivy_output_dir  = scanner.create_output_dir(safe_name, "Trivy_ARC")
    grype_output_dir  = scanner.create_output_dir(safe_name, "Grype_ARC")
    merged_output_dir = scanner.create_output_dir(safe_name, "Merged_ARC")
    df_trivy = df_grype = df_merged = None

    # Ensure folder for expected_fields_* templates
    os.makedirs("scanner", exist_ok=True)

    trivy_json = trivy_output_dir + f"/{safe_name}_trivy.json"
    grype_json = grype_output_dir + f"/{safe_name}_grype.json"

    # Trivy: use --input to scan from the saved Docker archive
    trivy_args = [
        "trivy", "image",
        "--input", str(tar_path),
        "--format", "json", "--output", trivy_json
    ]
    trivy_data = scanner.run_scan("trivy", image_name, trivy_args, "scanner/expected_fields_trivy.json")

    if trivy_data:
        df_trivy = scanner.prepare_dataframe(trivy_data, "trivy")
        if df_trivy is not None:
            scanner.save_markdown_report(df_trivy, image_name, safe_name, trivy_output_dir, "trivy")
            scanner.save_csv_report(df_trivy, safe_name, trivy_output_dir, "trivy")
            scanner.report_cve_distribution(trivy_data, trivy_output_dir, image_name, safe_name, scanner.get_missing_fields_by_cve, "trivy")
        else:
            print("[Trivy] No vulnerabilities to export: Empty DataFrame.")
    else:
        print("[Trivy] No JSON output (scan failed or tool not present). Skipping export and reporting.")

    # Grype: target docker-archive:<path>
    grype_args = [
        "grype", f"docker-archive:{tar_path}",
        "--output", "json", "--file", grype_json
    ]
    grype_data = scanner.run_scan("grype", image_name, grype_args, "scanner/expected_fields_grype.json")

    if grype_data:
        df_grype = scanner.prepare_dataframe(grype_data, "grype")
        if df_grype is not None:
            scanner.save_markdown_report(df_grype, image_name, safe_name, grype_output_dir, "grype")
            scanner.save_csv_report(df_grype, safe_name, grype_output_dir, "grype")
            scanner.report_cve_distribution(grype_data, grype_output_dir, image_name, safe_name, scanner.get_missing_fields_by_cve, "grype")
        else:
            print("[Grype] No vulnerabilities to export: Empty DataFrame.")
    else:
        print("[Grype] No JSON output (scan failed or tool not present). Skipping export and reporting.")

    # Merged
    if trivy_data and grype_data:
        print(f"[Merged] Performing merge and generating merged reports for: {image_name}") 
        merged_data = scanner.merge_trivy_grype(trivy_data, grype_data)
        if merged_data:
            df_merged = scanner.prepare_dataframe(merged_data, "merged")
            if df_merged is not None:
                scanner.save_markdown_report(df_merged, image_name, safe_name, merged_output_dir, "merged")
                scanner.save_csv_report(df_merged, safe_name, merged_output_dir, "merged")
            else:
                print("[Merged] No vulnerabilities to export: Empty DataFrame.")
        else:
            print("[Merged] Merge produced no records (no overlap or merge error).")
        
        # Compare Trivy vs Grype CVEs
        scanner.report_extra_occurrences(trivy_data, grype_data, "Grype", safe_name, merged_output_dir)
        scanner.compare_cve_sets(trivy_data, grype_data, image_name, safe_name, merged_output_dir)
    else:
        if not trivy_data and not grype_data:
            print("[Merged] Merge failed: both Trivy and Grype reports are missing.")
        elif not trivy_data:
            print("[Merged] Merge failed: Trivy report missing.")
        else:
            print("[Merged] Merge failed: Grype report missing.")
        print("[Merged] Skipped Extra & CVE comparison: both Trivy and Grype are needed.")

    if df_trivy is not None and df_grype is not None:
        scanner.report_discrepancies(df_trivy, df_grype, merged_output_dir, image_name, safe_name)
    else:
        print("[Merged] Discrepancy report skipped: Trivy/Grype DataFrame not available.")

    if df_trivy is not None and df_merged is not None:
        scanner.report_improvements(df_trivy, df_merged, ["FixedVersion", "CVSS"], "trivy", image_name, merged_output_dir, safe_name)
    else:
        print("[Improvement - Trivy] Report failed: need the merged DF and the Trivy one.")

    if df_grype is not None and df_merged is not None:
        scanner.report_improvements(df_grype, df_merged, ["FixedVersion", "CVSS"], "grype", image_name, merged_output_dir, safe_name)
    else:
        print("[Improvement - Grype] Report failed: need the merged DF and the Grype one.")

if __name__ == "__main__":
    run_pipeline("vulnerables/web-dvwa")
