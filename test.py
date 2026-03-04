import os
from contextlib import redirect_stdout, redirect_stderr

from pipeline import run_pipeline


if __name__ == "__main__":
    images = [
        "nginx:latest",
        "python:3.13-alpine",
        "alpine:3.16",
        "vulnerables/web-dvwa",
        "centos:7",
        "php:8.1-fpm",
    ]

    os.makedirs("outputs/scanner_reports", exist_ok=True)
    
    os.makedirs("scanner", exist_ok=True)

    log_path = "outputs/full_pipeline_report.txt"

    with open(log_path, "w", encoding="utf-8") as log, \
         redirect_stdout(log), redirect_stderr(log):

        for image_name in images:
            print(f"\n=== FULL PIPELINE for {image_name} ===")

            try:
               
                run_pipeline(image_name)
            except Exception as e:
                print(f"[ERROR] While processing {image_name}: {e!r}")

    print(f"Done. Log saved to {log_path}")
