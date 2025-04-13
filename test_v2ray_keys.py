import requests
import subprocess
import os
import json
import tempfile
import time
import platform
import zipfile
import tarfile
import io
import stat
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

# --- Configuration ---

# Map commands to source URLs (same as in the original JS)
SOURCE_URLS = {
    "key1": "https://raw.githubusercontent.com/FRDYAK/teryak-configs/main/sub1-configs",
    "key2": "https://raw.githubusercontent.com/SonzaiEkkusu/V2RayDumper/main/config.txt",
    "key3": "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "key4": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "key5": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt",
    "key6": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
    "hk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Hong_Kong.txt",
    "jp": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Japan.txt",
    "sg": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Singapore.txt",
    "us": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "tw": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Taiwan.txt",
    "uk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_Kingdom.txt",
}

OUTPUT_DIR = "output"  # Directory to save working keys
XRAY_PATH = "./xray"    # Path to xray executable
MAX_WORKERS = 10        # Number of parallel tests
REQUEST_TIMEOUT = 10    # Timeout for fetching source URLs
TEST_TIMEOUT = 15       # Timeout for xray test command (seconds)

# --- Xray Installation ---

def download_and_extract_xray():
    """Downloads and extracts the latest Xray core binary."""
    print("Checking/Downloading Xray...")
    try:
        # Get latest release info from GitHub API
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        release_info = response.json()
        tag_name = release_info['tag_name']
        print(f"Latest Xray version: {tag_name}")

        # Determine asset name based on OS (GitHub Actions uses Linux x64)
        system = platform.system().lower()
        machine = platform.machine().lower()

        if system == 'linux' and machine == 'x86_64':
            asset_name = "Xray-linux-64.zip"
        # Add more platforms if needed (e.g., macos, windows)
        # elif system == 'darwin' and machine == 'arm64':
        #    asset_name = "Xray-macos-arm64.zip"
        # elif system == 'windows' and machine == 'amd64':
        #     asset_name = "Xray-windows-64.zip"
        else:
             print(f"Unsupported platform: {system} {machine}. Assuming Linux x64 for download.")
             asset_name = "Xray-linux-64.zip" # Default for GitHub Actions

        asset_url = None
        for asset in release_info['assets']:
            if asset['name'] == asset_name:
                asset_url = asset['browser_download_url']
                break

        if not asset_url:
            raise ValueError(f"Could not find asset '{asset_name}' in release {tag_name}")

        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=60) # Longer timeout for download
        download_response.raise_for_status()

        # Extract directly from memory
        print("Extracting Xray...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                # Find the main executable ('xray' or 'xray.exe')
                exe_name = 'xray' if system != 'windows' else 'xray.exe'
                if exe_name in zf.namelist():
                    zf.extract(exe_name, path=".") # Extract to current dir
                    print(f"Extracted '{exe_name}'")
                else:
                     # Sometimes it's in a subdirectory, find it
                    found = False
                    for member in zf.namelist():
                        if member.endswith(exe_name):
                            zf.extract(member, path=".")
                             # Rename/move if needed, assuming it extracts like 'dir/xray'
                            extracted_path = os.path.join(".", member)
                            os.rename(extracted_path, XRAY_PATH)
                            # Clean up parent dir if created
                            if os.path.dirname(member):
                                os.rmdir(os.path.join(".", os.path.dirname(member)))
                            print(f"Extracted and moved '{member}' to '{XRAY_PATH}'")
                            found = True
                            break
                    if not found:
                        raise FileNotFoundError(f"'{exe_name}' not found within the zip file.")

        # Add handling for .tar.gz if needed for other platforms
        # elif asset_name.endswith(".tar.gz"):
        #     with tarfile.open(fileobj=io.BytesIO(download_response.content), mode="r:gz") as tf:
        #         # Find and extract logic similar to zip
        #         pass
        else:
            raise NotImplementedError(f"Extraction not implemented for {asset_name}")

        # Make executable on Linux/Mac
        if system != 'windows' and os.path.exists(XRAY_PATH):
            st = os.stat(XRAY_PATH)
            os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
            print(f"Made '{XRAY_PATH}' executable.")

        print("Xray download and extraction complete.")
        return True

    except Exception as e:
        print(f"Error downloading/extracting Xray: {e}")
        # If Xray already exists, try to use it
        if os.path.exists(XRAY_PATH):
            print("Using existing Xray binary.")
            # Ensure it's executable
            if platform.system() != 'windows':
                 st = os.stat(XRAY_PATH)
                 os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
            return True
        return False

# --- V2Ray Config Generation ---

def generate_v2ray_config(key_url):
    """Generates a minimal V2Ray JSON config for testing a key."""
    try:
        # Basic parsing (you might need more robust parsing for complex URLs)
        if key_url.startswith("vmess://"):
            # Basic VMess Base64 decode (needs proper library for robustness)
            import base64
            try:
                decoded_data = base64.b64decode(key_url[8:]).decode('utf-8')
                vmess_config = json.loads(decoded_data)
                # Extract necessary parts (add, port, id, aid, net, type, host, path, tls, sni)
                # This is a simplified example; real parsing is complex
                proxy_config = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": True}}], # Dummy inbound
                    "outbounds": [{
                        "protocol": "vmess",
                        "settings": {
                            "vnext": [{
                                "address": vmess_config.get("add", ""),
                                "port": int(vmess_config.get("port", 443)),
                                "users": [{"id": vmess_config.get("id", ""), "alterId": int(vmess_config.get("aid", 0))}]
                            }]
                        },
                        "streamSettings": {
                            "network": vmess_config.get("net", "tcp"),
                            "security": vmess_config.get("tls", ""), # "tls" or ""
                            "tlsSettings": {
                                "serverName": vmess_config.get("sni", vmess_config.get("host", "")),
                                "allowInsecure": False # Adjust if needed
                            },
                            "wsSettings": {
                                "path": vmess_config.get("path", "/"),
                                "headers": {"Host": vmess_config.get("host", vmess_config.get("add", ""))}
                            } if vmess_config.get("net") == "ws" else None,
                             "tcpSettings": {
                                "header": {"type": vmess_config.get("type", "none")} # For tcp http headers
                            } if vmess_config.get("net") == "tcp" and vmess_config.get("type") != "none" else None,
                            # Add other network types like kcp, grpc etc. if needed
                        }
                    }]
                }
                # Remove None settings for cleaner config
                if proxy_config["outbounds"][0]["streamSettings"]["wsSettings"] is None:
                    del proxy_config["outbounds"][0]["streamSettings"]["wsSettings"]
                if proxy_config["outbounds"][0]["streamSettings"]["tcpSettings"] is None:
                     del proxy_config["outbounds"][0]["streamSettings"]["tcpSettings"]
                if not proxy_config["outbounds"][0]["streamSettings"]["security"]:
                     del proxy_config["outbounds"][0]["streamSettings"]["tlsSettings"]


                return json.dumps(proxy_config, indent=2)

            except Exception as parse_error:
                # print(f"Failed to parse VMess URL: {key_url} - Error: {parse_error}")
                return None

        elif key_url.startswith("vless://"):
            # Simplified VLESS parsing
            try:
                parts = urlparse(key_url)
                uuid = parts.username
                address = parts.hostname
                port = parts.port or 443
                params = parse_qs(parts.query)

                security = params.get('security', [None])[0]
                sni = params.get('sni', [address])[0]
                fp = params.get('fp', [None])[0]
                pbk = params.get('pbk', [None])[0]
                sid = params.get('sid', [None])[0]
                flow = params.get('flow', [None])[0]
                network_type = params.get('type', ['tcp'])[0] # ws, grpc, tcp etc.
                host = params.get('host', [address])[0]
                path = params.get('path', ['/'])[0]
                # serviceName = params.get('serviceName', [None])[0] # for grpc

                proxy_config = {
                     "log": {"loglevel": "warning"},
                     "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": False}}], # Dummy inbound
                     "outbounds": [{
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": address,
                                "port": int(port),
                                "users": [{"id": uuid, "flow": flow if flow else ""}] # Flow might need specific format like "xtls-rprx-vision"
                            }]
                        },
                        "streamSettings": {
                            "network": network_type,
                            "security": security if security else "none", # "tls" or "reality" or "none"
                             "realitySettings": {
                                "serverName": sni,
                                "fingerprint": fp,
                                "publicKey": pbk,
                                "shortId": sid,
                            } if security == "reality" and pbk and sid else None,
                            "tlsSettings": {
                                "serverName": sni,
                                "fingerprint": fp,
                                "allowInsecure": False, # Adjust if needed
                            } if security == "tls" else None,
                            "wsSettings": {
                                "path": unquote(path),
                                "headers": {"Host": host}
                            } if network_type == "ws" else None,
                             # Add grpcSettings if needed
                            # "grpcSettings": {
                            #    "serviceName": serviceName
                            # } if network_type == "grpc" else None,
                        }
                    }]
                }

                 # Clean up None settings
                if proxy_config["outbounds"][0]["streamSettings"]["realitySettings"] is None:
                     del proxy_config["outbounds"][0]["streamSettings"]["realitySettings"]
                if proxy_config["outbounds"][0]["streamSettings"]["tlsSettings"] is None:
                     del proxy_config["outbounds"][0]["streamSettings"]["tlsSettings"]
                if proxy_config["outbounds"][0]["streamSettings"]["wsSettings"] is None:
                     del proxy_config["outbounds"][0]["streamSettings"]["wsSettings"]
                # if proxy_config["outbounds"][0]["streamSettings"]["grpcSettings"] is None:
                #    del proxy_config["outbounds"][0]["streamSettings"]["grpcSettings"]
                if not flow: # Remove flow if empty or None
                     del proxy_config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"]

                return json.dumps(proxy_config, indent=2)

            except Exception as parse_error:
                # print(f"Failed to parse VLESS URL: {key_url} - Error: {parse_error}")
                return None

        # Add parsers for trojan, ss etc. if needed

        else:
            # print(f"Unsupported key type: {key_url[:10]}...")
            return None
    except Exception as e:
        # print(f"Error generating config for {key_url[:20]}...: {e}")
        return None


# --- Key Testing ---

def test_v2ray_key(key_url):
    """Tests a single V2Ray key using xray -test."""
    config_json = generate_v2ray_config(key_url)
    if not config_json:
        return key_url, False # Return original key and False if config generation failed

    temp_config_file = None
    try:
        # Use tempfile for secure temporary file creation
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as tf:
            tf.write(config_json)
            temp_config_file = tf.name
        # print(f"Testing key: {key_url[:30]}... with config: {temp_config_file}")

        # Run xray -test command
        command = [XRAY_PATH, "-test", "-config", temp_config_file]
        process = subprocess.run(command, capture_output=True, text=True, timeout=TEST_TIMEOUT, check=False) # Don't check=True, handle return code

        # Check return code (0 means success)
        # print(f"Test Result for {key_url[:30]}... - Exit Code: {process.returncode}")
        # print(f"Stdout: {process.stdout.strip()}")
        # print(f"Stderr: {process.stderr.strip()}")
        return key_url, process.returncode == 0

    except subprocess.TimeoutExpired:
        # print(f"Test timed out for key: {key_url[:30]}...")
        return key_url, False
    except Exception as e:
        # print(f"Error testing key {key_url[:30]}...: {e}")
        return key_url, False
    finally:
        # Clean up temporary config file
        if temp_config_file and os.path.exists(temp_config_file):
            os.remove(temp_config_file)

# --- Main Execution ---

def main():
    start_time = time.time()

    if not download_and_extract_xray():
        print("Failed to get Xray binary. Aborting.")
        return

    if not os.path.exists(XRAY_PATH):
        print(f"Xray executable not found at {XRAY_PATH}. Aborting.")
        return

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_keys_to_test = []
    source_map = {} # Keep track of which command each key belongs to

    print("\nFetching keys from sources...")
    for command, url in SOURCE_URLS.items():
        try:
            print(f"Fetching {command} from {url}...")
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            keys = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"Found {len(keys)} keys for {command}.")
            for key in keys:
                 all_keys_to_test.append(key)
                 source_map[key] = command # Map key back to its source command
        except Exception as e:
            print(f"Failed to fetch keys for {command} from {url}: {e}")

    print(f"\nTotal keys to test: {len(all_keys_to_test)}")
    if not all_keys_to_test:
         print("No keys fetched, nothing to test.")
         return

    working_keys_by_command = {cmd: [] for cmd in SOURCE_URLS.keys()}
    tested_count = 0
    start_test_time = time.time()

    print(f"Starting tests with {MAX_WORKERS} workers...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in all_keys_to_test}
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            command_source = source_map.get(key)
            tested_count += 1
            try:
                _, is_working = future.result()
                if is_working and command_source:
                    working_keys_by_command[command_source].append(key)
                    # print(f"[OK] {key[:40]}...")
                # else:
                    # print(f"[FAIL] {key[:40]}...")
            except Exception as e:
                print(f"Error getting result for key {key[:40]}...: {e}")

            # Progress indicator
            if tested_count % 50 == 0 or tested_count == len(all_keys_to_test):
                elapsed = time.time() - start_test_time
                print(f"Tested {tested_count}/{len(all_keys_to_test)} keys... ({elapsed:.2f}s)")


    print("\n--- Test Results ---")
    total_working = 0
    for command, keys in working_keys_by_command.items():
        print(f"{command}: {len(keys)} working keys")
        total_working += len(keys)
        # Write working keys to output file
        output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
        try:
            with open(output_filename, 'w') as f:
                for key in keys:
                    f.write(key + '\n')
            print(f"  Saved working keys to {output_filename}")
        except Exception as e:
             print(f"  Error writing file {output_filename}: {e}")


    end_time = time.time()
    print(f"\nTotal working keys found: {total_working}")
    print(f"Script finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
