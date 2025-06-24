from scanner.docker_scanner import scan_docker_image

if __name__ == "__main__":
    print("\n=== Scanning nginx:latest ===")
    scan_docker_image("nginx:latest")

    print("\n=== Scanning python:3.13-alpine ===")
    scan_docker_image("python:3.13-alpine")

    print("\n=== Scanning alpine:3.16 ===")
    scan_docker_image("alpine:3.16")

    print("\n=== Scanning vulnerables/web-dvwa ===")
    scan_docker_image("vulnerables/web-dvwa")

    print("\n=== Scanning centos:7 ===")
    scan_docker_image("centos:7")

    print("\n=== Scanning php:8.1-fpm ===")
    scan_docker_image("php:8.1-fpm")
