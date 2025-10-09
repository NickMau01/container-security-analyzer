import os
import scanner.docker_scanner as scanner
from contextlib import redirect_stdout, redirect_stderr

if __name__ == "__main__":
    images = [
        "nginx:latest",
        "python:3.13-alpine",
        "alpine:3.16",
        "vulnerables/web-dvwa",
        "centos:7",
        "php:8.1-fpm"
    ]

    os.makedirs("outputs/scanner_reports", exist_ok=True)
    os.makedirs("scanner", exist_ok=True)

    log_path = "outputs/scanner_reports/scan_report.txt"
    with open(log_path, "w", encoding="utf-8") as log:
        with redirect_stdout(log), redirect_stderr(log):
            for image_name in images:
                print(f"\n=== Scanning {image_name} ===")
                safe_name = image_name.replace("/", "_").replace(":", "_")

                trivy_dir  = scanner.create_output_dir(safe_name, "Trivy")
                grype_dir  = scanner.create_output_dir(safe_name, "Grype")
                merged_dir = scanner.create_output_dir(safe_name, "Merged")

                df_trivy = df_grype = df_merged = None
                trivy_data = grype_data = None

                try:
                    # Trivy
                    trivy_json = os.path.join(trivy_dir, f"{safe_name}_trivy.json")
                    trivy_data = scanner.run_scan(
                        "trivy",
                        image_name,
                        ["trivy", "image", "--format", "json", "--output", trivy_json, image_name],
                        "scanner/expected_fields_trivy.json"
                    )
                    if trivy_data:
                        df_trivy = scanner.prepare_dataframe(trivy_data, "trivy")
                        if df_trivy is not None:
                            scanner.save_markdown_report(df_trivy, image_name, safe_name, trivy_dir, "trivy")
                            scanner.save_csv_report(df_trivy, safe_name, trivy_dir, "trivy")
                            scanner.report_cve_distribution(trivy_data, trivy_dir, image_name, safe_name,
                                                            scanner.get_missing_fields_by_cve, "trivy")
                        else:
                            print("[Trivy] No vulnerabilities to export: Empty DataFrame.")
                    else:
                        print("[Trivy] No JSON output (scan failed or tool not present). Skipping export and reporting.")

                    # Grype
                    grype_json = os.path.join(grype_dir, f"{safe_name}_grype.json")
                    grype_data = scanner.run_scan(
                        "grype",
                        image_name,
                        ["grype", image_name, "--output", "json", "--file", grype_json],
                        "scanner/expected_fields_grype.json",
                    )
                    if grype_data:
                        df_grype = scanner.prepare_dataframe(grype_data, "grype")
                        if df_grype is not None:
                            scanner.save_markdown_report(df_grype, image_name, safe_name, grype_dir, "grype")
                            scanner.save_csv_report(df_grype, safe_name, grype_dir, "grype")
                            scanner.report_cve_distribution(grype_data, grype_dir, image_name, safe_name,
                                                            scanner.get_missing_fields_by_cve, "grype")
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
                                scanner.save_markdown_report(df_merged, image_name, safe_name, merged_dir, "merged")
                                scanner.save_csv_report(df_merged, safe_name, merged_dir, "merged")
                            else:
                                print("[Merged] No vulnerabilities to export: Empty DataFrame.")
                        else:
                            print("[Merged] Merge produced no records (no overlap or merge error).")

                        # Compare Trivy vs Grype CVEs
                        scanner.report_extra_occurrences(trivy_data, grype_data, "Grype", safe_name, merged_dir)
                        scanner.compare_cve_sets(trivy_data, grype_data, image_name, safe_name, merged_dir)
                    else:
                        if not trivy_data and not grype_data:
                            print("[Merged] Merge failed: both Trivy and Grype reports are missing.")
                        elif not trivy_data:
                            print("[Merged] Merge failed: Trivy report missing.")
                        else:
                            print("[Merged] Merge failed: Grype report missing.")
                        print("[Merged] Skipped Extra & CVE comparison: both Trivy and Grype are needed.")

                    if df_trivy is not None and df_grype is not None:
                        scanner.report_discrepancies(df_trivy, df_grype, merged_dir, image_name, safe_name)
                    else:
                        print("[Merged] Discrepancy report skipped: Trivy/Grype DataFrame not available.")

                    if df_trivy is not None and df_merged is not None:
                        scanner.report_improvements(
                            orig_df=df_trivy,
                            merged_df=df_merged,
                            fields=["FixedVersion", "CVSS"],
                            tool_name="trivy",
                            image_name=image_name,
                            merged_dir=merged_dir,
                            safe_name=safe_name,
                        )
                    else:
                        print("[Improvement - Trivy] Report failed: need the merged DF and the Trivy one.")

                    if df_grype is not None and df_merged is not None:
                        scanner.report_improvements(
                            orig_df=df_grype,
                            merged_df=df_merged,
                            fields=["FixedVersion", "CVSS"],
                            tool_name="grype",
                            image_name=image_name,
                            merged_dir=merged_dir,
                            safe_name=safe_name,
                        )
                    else:
                        print("[Improvement - Grype] Report failed: need the merged DF and the Grype one.")

                except Exception as e:
                    print(f"[ERROR] While processing {image_name}: {e}")

    print(f"Done. Log saved to {log_path}")
