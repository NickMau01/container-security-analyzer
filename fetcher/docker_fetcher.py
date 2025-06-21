import docker
import os
import tarfile
import stat
import shutil

def fetch_image(image_name, output_dir="outputs/fetched_images", safe_mode=True):
    client = docker.from_env()

    # Image pull
    print(f"Pulling image: {image_name}")
    image = client.images.pull(image_name)

    # Creating output directory
    os.makedirs(output_dir, exist_ok=True)

    # Saving image as tar
    image_tar_path = os.path.join(output_dir, image_name.replace("/","_").replace(":","_") + ".tar")
    print(f"Saving image to {image_tar_path}")
    with open(image_tar_path, 'wb') as f:
        for chunk in image.save(named=True):
            f.write(chunk)
    
    # Extracting layers to a subfolder
    extracted_dir = os.path.join(output_dir, "extracted_" + image_name.replace("/","_").replace(":","_"))
    if os.path.exists(extracted_dir):
        print(f"Cleaning up previous directory: {extracted_dir}")
        
        def force_remove_readonly(func, path, _):
            os.chmod(path,stat.S_IWRITE)
            func(path)
        
        shutil.rmtree(extracted_dir,onexc=force_remove_readonly)

    os.makedirs(extracted_dir, exist_ok=True)
    print(f"Extracting image layers to: {extracted_dir}")

    def safe_filter(member, targetpath):
        if member.name.startswith("/") or ".." in member.name:
            return None
        return member
    
    def allow_all_filter(member, targetpath):
        return member # It's just to avoid warnings from Python 3.14
    
    filter_to_use = safe_filter if safe_mode else allow_all_filter

    with tarfile.open(image_tar_path,'r') as tar:
        tar.extractall(
            path=extracted_dir,
            filter=filter_to_use
            )
    
    print(f"Done. Image saved and extracted.")
    return {
        "image_tar": image_tar_path,
        "extracted_dir": extracted_dir
    }

if __name__ == "__main__":
    fetch_image("nginx:latest")