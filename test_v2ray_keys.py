import requests
import subprocess
import os
import json
import platform
import yaml
import time
from urllib.parse import urlparse, unquote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
SOURCE_URLS = {
    "key1": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",
    "key2": "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mixbase64",
    "key3": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
    "key4": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "key5": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "key6": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY.txt",
    "hk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Hong_Kong.txt",
    "jp": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Japan.txt",
    "sg": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Singapore.txt",
    "us": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "tw": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "uk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_Kingdom.txt",
}

OUTPUT_DIR = "subscription"
CLASH_PATH = "./clash"
MAX_WORKERS = 15
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 20
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


# --- Utility Functions ---
def retry_request(url, retries=MAX_RETRIES):
    """Retry logic for network-related requests."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
            if attempt < retries - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts.")


# --- Download and Setup Clash ---
def download_and_extract_clash():
    """Download and set up Clash binary from archived links."""
    print("Checking/Downloading Clash...")
    try:
        system = platform.system().lower()
        machine = platform.machine().lower()

        # Set the base URL for archived links
        base_url = "https://web.archive.org/web/20231003084307/https://github.com/Dreamacro/clash/releases/download/v1.18.0"

        # Determine the correct binary based on the system and architecture
        if system == "linux" and machine == "x86_64":
            clash_url = f"{base_url}/clash-linux-amd64-v1.18.0.gz"
        elif system == "linux" and machine == "aarch64":
            clash_url = f"{base_url}/clash-linux-arm64-v1.18.0.gz"
        elif system == "darwin" and machine == "x86_64":
            clash_url = f"{base_url}/clash-darwin-amd64-v1.18.0.gz"
        elif system == "darwin" and machine == "arm64":
            clash_url = f"{base_url}/clash-darwin-arm64-v1.18.0.gz"
        elif system == "windows":
            clash_url = f"{base_url}/clash-windows-amd64-v1.18.0.gz"
        elif system == "freebsd" and machine == "x86_64":
            clash_url = f"{base_url}/clash-freebsd-amd64-v1.18.0.gz"
        elif system == "freebsd" and machine == "i386":
            clash_url = f"{base_url}/clash-freebsd-386-v1.18.0.gz"
        else:
            raise ValueError(f"Unsupported system or architecture: {system} {machine}")

        print(f"Downloading Clash from {clash_url}...")
        response = retry_request(clash_url)

        # Save the downloaded file
        compressed_path = f"{CLASH_PATH}.gz"
        with open(compressed_path, "wb") as clash_file:
            clash_file.write(response.content)

        # Decompress the file
        print(f"Decompressing {compressed_path}...")
        import gzip
        with gzip.open(compressed_path, "rb") as f_in:
            with open(CLASH_PATH, "wb") as f_out:
                f_out.write(f_in.read())
        os.chmod(CLASH_PATH, 0o755)
        os.remove(compressed_path)
        print("Clash downloaded and set up successfully.")
        return True
    except Exception as e:
        print(f"Failed to download Clash: {e}")
        return False


# --- Generate Clash Configuration ---
def generate_clash_config(keys):
    """Generate a Clash config file for testing keys."""
    proxies = []
    for key in keys:
        protocol, url = key
        if protocol == "vmess":
            try:
                vmess_data = json.loads(base64.b64decode(url[8:]).decode("utf-8"))
                proxies.append({
                    "name": f"vmess-{vmess_data['ps']}",
                    "type": "vmess",
                    "server": vmess_data["add"],
                    "port": vmess_data["port"],
                    "uuid": vmess_data["id"],
                    "alterId": vmess_data.get("aid", 0),
                    "cipher": "auto",
                    "tls": vmess_data.get("tls", False),
                })
            except Exception as e:
                print(f"Error parsing VMess key: {e}")
        elif protocol == "vless":
            parsed = urlparse(url)
            proxies.append({
                "name": f"vless-{parsed.hostname}",
                "type": "vless",
                "server": parsed.hostname,
                "port": parsed.port or 443,
                "uuid": parsed.username,
                "cipher": "auto",
                "tls": True,
            })
        elif protocol == "trojan":
            parsed = urlparse(url)
            proxies.append({
                "name": f"trojan-{parsed.hostname}",
                "type": "trojan",
                "server": parsed.hostname,
                "port": parsed.port or 443,
                "password": parsed.username,
                "tls": True,
            })
        elif protocol == "ss":
            try:
                parsed = urlparse(url)
                method, password = base64.b64decode(parsed.username).decode("utf-8").split(":")
                proxies.append({
                    "name": f"ss-{parsed.hostname}",
                    "type": "ss",
                    "server": parsed.hostname,
                    "port": parsed.port or 443,
                    "cipher": method,
                    "password": password,
                })
            except Exception as e:
                print(f"Error parsing SS key: {e}")

    # Add a default proxy group even if no proxies are found
    clash_config = {
        "proxies": proxies,
        "proxy-groups": [{
            "name": "auto",
            "type": "select",
            "proxies": [p["name"] for p in proxies] if proxies else ["DIRECT"],  # Fallback to DIRECT if no proxies
        }],
        "rules": ["MATCH,auto"],
    }

    with open("clash_config.yaml", "w") as config_file:
        yaml.dump(clash_config, config_file, default_flow_style=False)

    if not proxies:
        print("Warning: No proxies were added to the Clash configuration.")
    return len(proxies)


# --- Test Keys with Clash ---
def test_keys_with_clash():
    """Run Clash to test keys."""
    print("Testing keys using Clash...")
    try:
        process = subprocess.run(
            [CLASH_PATH, "-f", "clash_config.yaml"],
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT,
        )
        print(process.stdout)
        return process.returncode == 0
    except Exception as e:
        print(f"Error running Clash: {e}")
        return False


# --- Main Execution ---
def main():
    print("Starting V2Ray Key Testing Script...")
    if not download_and_extract_clash():
        print("FATAL: Failed to set up Clash. Aborting.")
        return

    if not os.path.exists(CLASH_PATH) or not os.access(CLASH_PATH, os.X_OK):
        print(f"FATAL: Clash executable not found or not executable at {CLASH_PATH}. Aborting.")
        return

    print(f"Using Clash executable at: {os.path.abspath(CLASH_PATH)}")
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Fetch keys
    all_keys = []
    for protocol, url in SOURCE_URLS.items():
        try:
            response = retry_request(url)
            print(f"Fetched content from {url}: {response.text[:500]}")  # Debugging output
            keys = [line.strip() for line in response.text.splitlines() if line.strip()]
            all_keys.extend([(protocol, key) for key in keys])
        except Exception as e:
            print(f"Failed to fetch keys from {url}: {e}")

    # Debug: Check fetched keys
    print(f"Total fetched keys: {len(all_keys)}")
    for protocol, key in all_keys[:5]:  # Print first 5 keys for debugging
        print(f"Protocol: {protocol}, Key: {key}")

    # Generate config and test keys
    if not all_keys:
        print("No keys fetched. Exiting.")
        return

    num_proxies = generate_clash_config(all_keys)
    print(f"Generated Clash config with {num_proxies} proxies.")

    if num_proxies == 0:
        print("No valid proxies found. Skipping Clash test.")
        return

    if test_keys_with_clash():
        print("Key testing completed successfully.")
    else:
        print("Key testing failed.")

    print("Script finished.")

if __name__ == "__main__":
    main()
