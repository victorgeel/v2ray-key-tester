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
import base64                     # For Base64 decoding
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus # For URL parsing
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
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

OUTPUT_DIR = "output"
XRAY_PATH = "./xray"
MAX_WORKERS = 15        # Increase workers slightly if feasible
REQUEST_TIMEOUT = 15    # Slightly longer timeout for fetching sources
TEST_TIMEOUT = 18       # Slightly longer timeout for xray test

# --- Xray Installation (same as before) ---
def download_and_extract_xray():
    """Downloads and extracts the latest Xray core binary."""
    print("Checking/Downloading Xray...")
    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        release_info = response.json()
        tag_name = release_info['tag_name']
        print(f"Latest Xray version: {tag_name}")

        system = platform.system().lower()
        machine = platform.machine().lower()
        asset_name = "Xray-linux-64.zip" # Default for GitHub Actions
        if system == 'linux' and machine == 'aarch64': # Support for ARM64 runners if used
             asset_name = "Xray-linux-arm64-v8a.zip"
        # Add other platforms if needed

        asset_url = None
        for asset in release_info['assets']:
            if asset['name'] == asset_name:
                asset_url = asset['browser_download_url']
                break
        if not asset_url: raise ValueError(f"Could not find asset '{asset_name}'")

        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=90) # Even longer for download
        download_response.raise_for_status()

        print("Extracting Xray...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray'
                extracted = False
                for member in zf.namelist():
                    # Handle cases where it might be in a subdirectory
                    if member.endswith(exe_name) and not member.startswith('__MACOSX'):
                        zf.extract(member, path=".")
                        extracted_path = os.path.join(".", member)
                        # If it was extracted inside a folder, move it to current dir
                        if os.path.dirname(member):
                            os.rename(extracted_path, XRAY_PATH)
                            # Clean up empty dir if possible
                            try:
                                os.rmdir(os.path.join(".", os.path.dirname(member)))
                            except OSError:
                                pass # Ignore if directory is not empty or other issues
                        else:
                             # If extracted directly, rename if needed
                             if extracted_path != XRAY_PATH:
                                os.rename(extracted_path, XRAY_PATH)

                        print(f"Extracted '{member}' to '{XRAY_PATH}'")
                        extracted = True
                        break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' not found within the zip file.")
        else: raise NotImplementedError(f"Extraction not implemented for {asset_name}")

        if system != 'windows' and os.path.exists(XRAY_PATH):
            st = os.stat(XRAY_PATH)
            os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
            print(f"Made '{XRAY_PATH}' executable.")
        print("Xray download and extraction complete.")
        return True
    except Exception as e:
        print(f"Error downloading/extracting Xray: {e}")
        if os.path.exists(XRAY_PATH):
            print("Using existing Xray binary.")
            if platform.system() != 'windows':
                 st = os.stat(XRAY_PATH)
                 os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
            return True
        return False

# --- Enhanced V2Ray Config Generation ---

def generate_config(key_url):
    """Generates a minimal Xray JSON config for testing various key types."""
    try:
        key_url = key_url.strip()
        parsed_url = urlparse(key_url)
        protocol = parsed_url.scheme
        config = None

        # Common settings template
        base_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": False}}], # Dummy inbound
            "outbounds": [{
                "protocol": protocol,
                "settings": {},
                "streamSettings": {}
            }]
        }

        if protocol == "vmess":
            # Decode Base64 part
            try:
                vmess_json_str = base64.b64decode(key_url[8:]).decode('utf-8')
                vmess_params = json.loads(vmess_json_str)

                base_config["outbounds"][0]["settings"]["vnext"] = [{
                    "address": vmess_params.get("add", ""),
                    "port": int(vmess_params.get("port", 443)),
                    "users": [{"id": vmess_params.get("id", ""), "alterId": int(vmess_params.get("aid", 0)), "security": vmess_params.get("scy", "auto")}]
                }]
                stream_settings = {
                    "network": vmess_params.get("net", "tcp"),
                    "security": vmess_params.get("tls", "none"), # "tls" or "none"
                }
                if stream_settings["security"] == "tls":
                     stream_settings["tlsSettings"] = {
                         "serverName": vmess_params.get("sni", vmess_params.get("host", "")),
                         "allowInsecure": False # Default, adjust if needed
                     }
                # Network specific settings
                net_type = stream_settings["network"]
                if net_type == "ws":
                     stream_settings["wsSettings"] = {
                         "path": vmess_params.get("path", "/"),
                         "headers": {"Host": vmess_params.get("host", vmess_params.get("add", ""))}
                     }
                elif net_type == "tcp" and vmess_params.get("type") == "http":
                     stream_settings["tcpSettings"] = {
                         "header": {
                             "type": "http",
                             "request": {
                                 "path": [vmess_params.get("path", "/")],
                                 "headers": {"Host": vmess_params.get("host", "").split(',')} # Host header might be comma-separated
                             }
                         }
                     }
                # Add other network types like grpc, kcp if needed
                base_config["outbounds"][0]["streamSettings"] = stream_settings
                config = base_config
            except Exception as e:
                # print(f"Failed parsing VMess JSON: {e} for key {key_url[:20]}")
                return None

        elif protocol == "vless":
            try:
                uuid = parsed_url.username
                address = parsed_url.hostname
                port = int(parsed_url.port or 443)
                params = parse_qs(parsed_url.query)

                base_config["outbounds"][0]["settings"]["vnext"] = [{
                    "address": address,
                    "port": port,
                    "users": [{"id": uuid, "flow": params.get('flow', [None])[0] or ""}]
                }]
                stream_settings = {
                    "network": params.get('type', ['tcp'])[0],
                    "security": params.get('security', ['none'])[0], # tls, reality, none
                }
                sec_type = stream_settings["security"]
                if sec_type == "tls":
                     stream_settings["tlsSettings"] = {
                         "serverName": params.get('sni', [params.get('peer', [address])[0]])[0],
                         "fingerprint": params.get('fp', [''])[0],
                         "allowInsecure": False,
                     }
                elif sec_type == "reality":
                     stream_settings["realitySettings"] = {
                         "serverName": params.get('sni', [params.get('peer', [address])[0]])[0],
                         "fingerprint": params.get('fp', [''])[0],
                         "shortId": params.get('sid', [''])[0],
                         "publicKey": params.get('pbk', [''])[0],
                         "spiderX": params.get('spx', ['/'])[0],
                     }
                # Network specific
                net_type = stream_settings["network"]
                if net_type == "ws":
                    stream_settings["wsSettings"] = {
                        "path": unquote_plus(params.get('path', ['/'])[0]),
                        "headers": {"Host": params.get('host', [address])[0]}
                    }
                elif net_type == "grpc":
                    stream_settings["grpcSettings"] = {
                        "serviceName": unquote_plus(params.get('serviceName', [''])[0])
                    }
                # Add tcp (usually no extra settings needed unless header type specified)
                base_config["outbounds"][0]["streamSettings"] = stream_settings
                config = base_config
            except Exception as e:
                # print(f"Failed parsing VLESS URL: {e} for key {key_url[:20]}")
                return None

        elif protocol == "trojan":
            try:
                password = parsed_url.username
                address = parsed_url.hostname
                port = int(parsed_url.port or 443)
                params = parse_qs(parsed_url.query)

                base_config["outbounds"][0]["settings"]["servers"] = [{
                    "address": address,
                    "port": port,
                    "password": password
                }]
                # Stream settings are crucial for Trojan
                stream_settings = {
                    "network": params.get('type', ['tcp'])[0], # Often ws or tcp
                    "security": params.get('security', ['tls'])[0], # Usually tls
                }
                if stream_settings["security"] == "tls":
                     stream_settings["tlsSettings"] = {
                         "serverName": params.get('sni', [params.get('peer', [address])[0]])[0],
                         "fingerprint": params.get('fp', [''])[0],
                         "allowInsecure": False,
                     }
                # Network specific
                net_type = stream_settings["network"]
                if net_type == "ws":
                     stream_settings["wsSettings"] = {
                         "path": unquote_plus(params.get('path', ['/'])[0]),
                         "headers": {"Host": params.get('host', [address])[0]}
                     }
                # Add grpc if needed
                base_config["outbounds"][0]["streamSettings"] = stream_settings
                config = base_config
            except Exception as e:
                # print(f"Failed parsing Trojan URL: {e} for key {key_url[:20]}")
                return None

        elif protocol == "ss": # Shadowsocks
             try:
                 # Format: ss://method:password@server:port#remark
                 # Or Base64 encoded: ss://base64(method:password)@server:port#remark
                 user_info_part = parsed_url.netloc.split('@')[0]
                 server_part = parsed_url.netloc.split('@')[1]
                 address = server_part.split(':')[0]
                 port = int(server_part.split(':')[1])

                 decoded_user_info = ""
                 try:
                      # Try decoding Base64 user info first
                      # Need to add padding if missing
                      padding = '=' * (-len(user_info_part) % 4)
                      decoded_user_info = base64.b64decode(user_info_part + padding).decode('utf-8')
                      # print(f"Decoded SS user info: {decoded_user_info}")
                 except Exception:
                      # If decode fails, assume plain method:password
                      decoded_user_info = unquote_plus(user_info_part)
                      # print(f"Using plain SS user info: {decoded_user_info}")


                 method, password = decoded_user_info.split(':', 1)

                 base_config["outbounds"][0]["settings"]["servers"] = [{
                     "address": address,
                     "port": port,
                     "method": method,
                     "password": password
                 }]
                 # Shadowsocks usually doesn't need complex streamSettings for basic test
                 base_config["outbounds"][0]["streamSettings"]["network"] = "tcp" # Default for test

                 config = base_config
             except Exception as e:
                 # print(f"Failed parsing SS URL: {e} for key {key_url[:20]}")
                 return None

        else:
            # print(f"Unsupported protocol: {protocol} for key {key_url[:20]}")
            return None

        # Clean up empty stream settings if needed
        if not config["outbounds"][0]["streamSettings"]:
             del config["outbounds"][0]["streamSettings"]

        return json.dumps(config, indent=2) if config else None

    except Exception as e:
        # Catch any unexpected error during parsing/generation
        # print(f"Generic error generating config for {key_url[:20]}...: {e}")
        return None

# --- Key Testing (same as before, uses generate_config) ---
def test_v2ray_key(key_url):
    """Tests a single V2Ray key using xray -test."""
    config_json = generate_config(key_url) # Use the enhanced generator
    if not config_json:
        # print(f"Skipping test for {key_url[:30]}... (config generation failed)")
        return key_url, False

    temp_config_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as tf:
            tf.write(config_json)
            temp_config_file = tf.name

        command = [XRAY_PATH, "test", "-config", temp_config_file] # Use 'test' command
        process = subprocess.run(command, capture_output=True, text=True, timeout=TEST_TIMEOUT, check=False)

        # Xray test returns 0 on success
        # print(f"Test Result for {key_url[:30]}... - Code: {process.returncode} // Stdout: {process.stdout.strip()} // Stderr: {process.stderr.strip()}")
        return key_url, process.returncode == 0

    except subprocess.TimeoutExpired:
        # print(f"Test timed out for key: {key_url[:30]}...")
        return key_url, False
    except Exception as e:
        # print(f"Error testing key {key_url[:30]}...: {e}")
        return key_url, False
    finally:
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

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_keys_to_test = []
    source_map = {} # Map key back to its command source

    print("\nFetching keys from sources...")
    for command, url in SOURCE_URLS.items():
        keys_from_source = []
        try:
            print(f"Fetching {command} from {url}...")
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            raw_data = response.text
            processed_data = raw_data # Assume plain text initially

            # --- Base64 Detection/Decoding ---
            try:
                # Remove potential whitespace before checking/decoding
                potential_b64 = raw_data.replace('\n', '').replace('\r', '').strip()
                # Basic check if it might be Base64 (length, charset)
                if len(potential_b64) > 20 and len(potential_b64) % 4 == 0 and \
                   all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in potential_b64):

                    decoded_bytes = base64.b64decode(potential_b64)
                    decoded_string = decoded_bytes.decode('utf-8')
                    # Check if decoded string contains common V2Ray prefixes
                    if any(prefix in decoded_string for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
                        print(f"  Detected Base64 content for {command}, using decoded data.")
                        processed_data = decoded_string
                    else:
                        print(f"  Decoded Base64 for {command} doesn't look like keys, treating as plain text.")
                        # Keep processed_data = raw_data
                else:
                     print(f"  Content for {command} doesn't look like Base64, treating as plain text.")
                     # Keep processed_data = raw_data

            except Exception as decode_error:
                print(f"  Base64 decoding failed for {command} (Error: {decode_error}), treating as plain text.")
                # Keep processed_data = raw_data

            # --- Extract Keys ---
            keys_from_source = [
                line.strip() for line in processed_data.splitlines()
                if line.strip() and any(line.strip().startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"])
            ]
            print(f"  Found {len(keys_from_source)} potential keys for {command} after processing.")

            for key in keys_from_source:
                 all_keys_to_test.append(key)
                 source_map[key] = command

        except Exception as e:
            print(f"Failed to fetch/process keys for {command} from {url}: {e}")

    print(f"\nTotal potential keys to test: {len(all_keys_to_test)}")
    if not all_keys_to_test:
         print("No keys fetched, nothing to test.")
         # Create empty output files so rclone doesn't fail/delete old ones if needed
         for command in SOURCE_URLS.keys():
             output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
             open(output_filename, 'w').close() # Create empty file
         print("Created empty output files.")
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
            except Exception as e:
                # print(f"Error getting result for key {key[:40]}...: {e}")
                pass # Avoid stopping the whole process for one key error

            if tested_count % 100 == 0 or tested_count == len(all_keys_to_test):
                elapsed = time.time() - start_test_time
                rate = tested_count / elapsed if elapsed > 0 else 0
                print(f"Tested {tested_count}/{len(all_keys_to_test)} keys... ({elapsed:.2f}s, {rate:.1f} keys/s)")

    print("\n--- Test Results ---")
    total_working = 0
    for command, keys in working_keys_by_command.items():
        print(f"{command}: {len(keys)} working keys")
        total_working += len(keys)
        output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
        try:
            # Sort keys alphabetically before saving for consistent output (optional)
            keys.sort()
            with open(output_filename, 'w') as f:
                for key in keys:
                    f.write(key + '\n')
            # print(f"  Saved working keys to {output_filename}")
        except Exception as e:
             print(f"  Error writing file {output_filename}: {e}")

    end_time = time.time()
    print(f"\nTotal working keys found and saved: {total_working}")
    print(f"Script finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
