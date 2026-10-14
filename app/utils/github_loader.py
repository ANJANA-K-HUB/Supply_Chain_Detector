import base64
import os
import zipfile
import tempfile
import requests

def fetch_dependencies_from_github(repo_url: str):
    """
    Takes a GitHub repo URL and fetches dependency configuration files
    using a fallback mechanism (requirements.txt -> pyproject.toml -> setup.py).
    """
    clean_url = repo_url.rstrip("/")
    if "/tree/" in clean_url:
        clean_url = clean_url.split("/tree/")[0]
    elif "/blob/" in clean_url:
        clean_url = clean_url.split("/blob/")[0]
        
    clean_path = clean_url.replace("https://github.com/", "")
    parts = clean_path.split("/")
    
    if len(parts) < 2:
        raise ValueError("Invalid GitHub repository URL format.")
    
    owner, repo = parts[0], parts[1]
    headers = {"Accept": "application/vnd.github.v3+json"}
    
    candidate_files = ["requirements.txt", "pyproject.toml", "setup.py"]
    
    for filename in candidate_files:
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            file_data = response.json()
            file_content_encoded = file_data.get("content", "")
            file_bytes = base64.b64decode(file_content_encoded)
            file_content = file_bytes.decode("utf-8")
            print(f"[*] Found dependency file: {filename}")
            return filename, file_content
            
    raise Exception("Could not find any supported dependency file (requirements.txt, pyproject.toml, setup.py) in the repository root.")
def download_repo_zip(repo_url: str) -> str:
    """
    Downloads the repository source code as a ZIP archive from GitHub 
    and extracts it into a temporary directory. Returns the path to the extracted folder.
    """
    # Clean up URL by stripping trailing paths like /tree/main, /blob/main, etc.
    clean_url = repo_url.rstrip("/")
    if "/tree/" in clean_url:
        clean_url = clean_url.split("/tree/")[0]
    elif "/blob/" in clean_url:
        clean_url = clean_url.split("/blob/")[0]
        
    if clean_url.endswith(".git"):
        clean_url = clean_url[:-4]
        
    temp_dir = tempfile.mkdtemp()
    
    for branch in ["main", "master"]:
        archive_url = f"{clean_url}/archive/refs/heads/{branch}.zip"
        response = requests.get(archive_url, stream=True)
        if response.status_code == 200:
            zip_path = os.path.join(temp_dir, "repo.zip")
            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            os.remove(zip_path)
            
            extracted_folders = [os.path.join(temp_dir, d) for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
            if extracted_folders:
                return extracted_folders[0]
                
    raise Exception("Failed to download repository source code archive from GitHub.")