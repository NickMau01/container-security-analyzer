from scanner.docker_scanner import scan_docker_image
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
                scan_docker_image(img)
