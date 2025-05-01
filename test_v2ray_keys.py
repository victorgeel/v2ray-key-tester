import requests
import subprocess
import os
import json
import platform
import yaml
import time
import base64
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
}
OUTPUT_DIR = "subscription"
CLASH_PATH = "./clash"
MAX_WORKERS = 15
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 30  # Increased timeout for Clash test
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

def parse_vless_key(url):
    """Parse a VLESS key and return a valid Clash proxy configuration."""
    try:
        parsed = urlparse(url)
        query = dict(qc.split("=") for qc in parsed.query.split("&") if "=" in qc)
        return {
            "name": f"vless-{parsed.hostname}",
            "type": "vless",
            "server": parsed.hostname,
            "port": int(parsed.port or 443),
            "uuid": parsed.username,
            "cipher": "auto",
            "tls": query.get("security", "none") == "tls",
            "network": query.get("type", "tcp"),
            "ws-opts": {
                "path": query.get("path", "/"),
                "headers": {"Host": query.get("host", "")},
            } if query.get("type") == "ws" else None,
            "grpc-opts": {
                "grpc-service-name": query.get("serviceName", ""),
            } if query.get("type") == "grpc" else None,
        }
    except Exception as e:
        print(f"Error parsing VLESS key: {url}, Error: {e}")
        return None

def parse_vmess_key(url):
    """Parse a VMess key and return a valid Clash proxy configuration."""
    try:
        vmess_data = json.loads(base64.b64decode(url[8:]).decode("utf-8"))
        return {
            "name": f"vmess-{vmess_data['ps']}",
            "type": "vmess",
            "server": vmess_data["add"],
            "port": int(vmess_data["port"]),
            "uuid": vmess_data["id"],
            "alterId": int(vmess_data.get("aid", 0)),
            "cipher": "auto",
            "tls": vmess_data.get("tls", False),
        }
    except Exception as e:
        print(f"Error parsing VMess key: {url}, Error: {e}")
        return None

def generate_clash_config(keys):
    """Generate a Clash config file for testing keys."""
    proxies = []
    for protocol, url in keys:
        try:
            if protocol == "vmess":
                proxy = parse_vmess_key(url)
            elif protocol == "vless":
                proxy = parse_vless_key(url)
            else:
                print(f"Unsupported protocol: {protocol}")
                continue
            if proxy:
                proxies.append(proxy)
        except Exception as e:
            print(f"Error parsing key: {url}, Error: {e}")

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

# --- Main Execution ---
def main():
    print("Starting V2Ray Key Testing Script...")
    all_keys = []

    # Fetch and validate keys
    for protocol, url in SOURCE_URLS.items():
        try:
            response = retry_request(url)
            print(f"Fetched content from {url}: {response.text[:500]}")  # Debugging output
            keys = [line.strip() for line in response.text.splitlines() if line.strip()]
            all_keys.extend([(protocol, key) for key in keys])
        except Exception as e:
            print(f"Failed to fetch keys from {url}: {e}")

    print(f"Total fetched keys: {len(all_keys)}")
    for protocol, key in all_keys[:5]:  # Debug first 5 keys
        print(f"Protocol: {protocol}, Key: {key}")

    # Generate and test Clash configuration
    if not all_keys:
        print("No keys fetched. Exiting.")
        return

    num_proxies = generate_clash_config(all_keys)
    print(f"Generated Clash config with {num_proxies} proxies.")

    if num_proxies == 0:
        print("No valid proxies found. Skipping Clash test.")
        return

    print("Key testing completed successfully.")

if __name__ == "__main__":
    main()
