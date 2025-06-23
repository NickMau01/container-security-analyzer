import subprocess
import json

def scan_docker_image(image_name, output_file="vulns_docker.json"):
    print(f"Scanning Docker image: {image_name}")
    
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
        with open(output_file) as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading/parsing JSON file: {e}")
        return None
    
    # Calculate the total vulnerabilities by adding them in all the "Results"
    vuln_count = sum(len(r.get("Vulnerabilities", [])) for r in data.get("Results", []))
    print(f"Total vulnerabilities found: {vuln_count}")

    # Returns the full contents of the JSON for future use
    return data

if __name__ == "__main__":
    scan_docker_image("nginx:latest")