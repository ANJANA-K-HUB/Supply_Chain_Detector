import requests
import os

def analyze_package_behavior(package_name: str, version: str = None):
    """
    Queries the official PyPI JSON API to analyze package metadata, 
    release history, maintainers, and supply-chain risk indicators.
    """
    pypi_url = f"https://pypi.org/pypi/{package_name}/json"
    
    behavior_data = {
        "exists_on_pypi": False,
        "author": "Unknown",
        "release_count": 0,
        "latest_release_date": None,
        "risk_indicators": []
    }
    
    try:
        response = requests.get(pypi_url, timeout=5)
        
        # Check for Typosquatting / Non-existent Package
        if response.status_code == 404:
            behavior_data["risk_indicators"].append({
                "type": "Typosquatting / Missing Package",
                "severity": "High",
                "message": f"Package '{package_name}' was not found on official PyPI. It may be a private package or a typosquatting attempt."
            })
            return behavior_data
            
        if response.status_code == 200:
            data = response.json()
            behavior_data["exists_on_pypi"] = True
            
            info = data.get("info", {})
            behavior_data["author"] = info.get("author", "Unknown")
            behavior_data["summary"] = info.get("summary", "")
            
            # Analyze release count and maturity
            releases = data.get("releases", {})
            behavior_data["release_count"] = len(releases)
            
            # Check specific version upload date if version is provided
            if version and version in releases:
                version_files = releases[version]
                if version_files:
                    upload_time_str = version_files[0].get("upload_time_iso_8601")
                    if upload_time_str:
                        behavior_data["latest_release_date"] = upload_time_str
                        
            # Heuristic: Brand-new packages with very few releases can be suspicious
            if len(releases) < 3:
                behavior_data["risk_indicators"].append({
                    "type": "Low Release Maturity",
                    "severity": "Medium",
                    "message": f"Package '{package_name}' has very low release maturity ({len(releases)} total release(s))."
                })
                
        return behavior_data
        
    except Exception as e:
        print(f"Error checking package behavior for {package_name}: {e}")
        return behavior_data