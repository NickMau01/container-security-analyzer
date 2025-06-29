import os
from scanner.docker_scanner import scan_docker_image, prepare_vulnerability_dataframe, save_markdown_report, save_csv_report
from contextlib import redirect_stdout, redirect_stderr

if __name__ == "__main__":
    images = [
        "nginx:latest",
        "python:3.13-alpine",
        "alpine:3.16",
        "vulnerables/web-dvwa",
        "centos:7",
        "php:8.1-fpm",
    ]

    with open("outputs/scanner_reports/scan_report.txt", "w", encoding="utf-8") as log:
         with redirect_stdout(log), redirect_stderr(log):
            for img in images:
                print(f"\n=== Scanning {img} ===")
                report = scan_docker_image(img)
                if report:
                    df, image = prepare_vulnerability_dataframe(report)
                    if df is not None:
                        image_folder = os.path.join("outputs/scanner_reports", image.replace("/", "_").replace(":", "_"))
                        save_markdown_report(df, image, output_dir=image_folder)
                        save_csv_report(df, image, output_dir=image_folder)
