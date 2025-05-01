import requests
import subprocess
import os
import json
import tempfile
import time
import platform
import yaml
from urllib.parse import urlparse, unquote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
SOURCE_URLS = {
    "key1": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",
    "key2": "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mixbase64",
    "key3": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
    "key5": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "key4": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
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


# --- Download and Setup Clash ---
def download_and_extract_clash():
    """Download and set up Clash binary."""
    print("Checking/Downloading Clash...")
    try:
        system = platform.system().lower()
        machine = platform.machine().lower()
        clash_url = "https://github.com/Dreamacro/clash/releases/latest/download/clash-linux-amd64"

        if system == "windows":
            clash_url = "https://github.com/Dreamacro/clash/releases/latest/download/clash-windows-amd64.exe"
        elif system == "darwin":
            clash_url = "https://github.com/Dreamacro/clash/releases/latest/download/clash-darwin-amd64"

        print(f"Downloading Clash from {clash_url}...")
        response = requests.get(clash_url, stream=True, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        with open(CLASH_PATH, "wb") as clash_file:
            for chunk in response.iter_content(chunk_size=8192):
                clash_file.write(chunk)

        if system != "windows":
            os.chmod(CLASH_PATH, 0o755)
        print("Clash downloaded and set up successfully.")
        return True
    except Exception as e:
        print(f"Failed to download Clash: {e}")
        return False


# --- Generate Clash Configuration ---
def generate_clash_config(keys):
    """Generate a Clash config file for testing keys."""
    proxies = []
    for protocol, key in keys:
        if protocol == "vmess":
            # Parse VMess key to extract details
            try:
                vmess_data = json.loads(base64.b64decode(key[8:]).decode("utf-8"))
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
            # Parse VLess key to extract details
            parsed = urlparse(key)
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
            # Parse Trojan key to extract details
            parsed = urlparse(key)
            proxies.append({
                "name": f"trojan-{parsed.hostname}",
                "type": "trojan",
                "server": parsed.hostname,
                "port": parsed.port or 443,
                "password": parsed.username,
                "tls": True,
            })
        elif protocol == "ss":
            # Parse Shadowsocks key to extract details
            try:
                parsed = urlparse(key)
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

    clash_config = {
        "proxies": proxies,
        "proxy-groups": [{
            "name": "auto",
            "type": "select",
            "proxies": [p["name"] for p in proxies],
        }],
        "rules": ["MATCH,auto"],
    }

    with open("clash_config.yaml", "w") as config_file:
        yaml.dump(clash_config, config_file, default_flow_style=False)
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
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            keys = [line.strip() for line in response.text.splitlines() if line.strip()]
            all_keys.extend([(protocol, key) for key in keys])
        except Exception as e:
            print(f"Failed to fetch keys from {url}: {e}")

    # Generate config and test keys
    if not all_keys:
        print("No keys fetched. Exiting.")
        return

    num_proxies = generate_clash_config(all_keys)
    print(f"Generated Clash config with {num_proxies} proxies.")

    if test_keys_with_clash():
        print("Key testing completed successfully.")
    else:
        print("Key testing failed.")

    print("Script finished.")


if __name__ == "__main__":
    main()
