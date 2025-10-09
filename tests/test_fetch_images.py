from fetcher.docker_fetcher import fetch_image

if __name__ == "__main__":
    print("\n=== Fetching nginx:latest ===")
    fetch_image("nginx:latest", safe_mode=False)

    print("\n=== Fetching python:3.13-alpine ===")
    fetch_image("python:3.13-alpine", safe_mode=False)

    print("\n=== Fetching alpine:3.16 ===")
    fetch_image("alpine:3.16", safe_mode=False)

    print("\n=== Fetching vulnerables/web-dvwa ===")
    fetch_image("vulnerables/web-dvwa", safe_mode=True)

    print("\n=== Fetching centos:7 ===")
    fetch_image("centos:7", safe_mode=False)

    print("\n=== Fetching php:8.1-fpm ===")
    fetch_image("php:8.1-fpm", safe_mode=False)