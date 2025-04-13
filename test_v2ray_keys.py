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
import base64
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
SOURCE_URLS = {
    # "key1": "DEAD_URL_REMOVED", # Remove or replace dead links like the FRDYAK one
    "key1": "https://raw.githubusercontent.com/darknessm427/V2ray-Sub-Collector/main/Sort-By-Protocol/Darkness_vmess.txt", # User added
    "key2": "https://raw.githubusercontent.com/SonzaiEkkusu/V2RayDumper/main/config.txt",
    "key3": "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "key4": "https://raw.githubusercontent.com/shabane/kamaji/master/hub/b64/vless.txt", # User added
    "key5": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt",
    "key6": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
    "hk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Hong_Kong.txt",
    "jp": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Japan.txt",
    "sg": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Singapore.txt",
    "us": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "tw": "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/vless.txt", # User added
    "uk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_Kingdom.txt",
}

OUTPUT_DIR = "output"
XRAY_PATH = "./xray"
MAX_WORKERS = 15
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 20

# --- Xray Installation ---
def download_and_extract_xray():
    """Downloads and extracts the latest Xray core binary."""
    print("Checking/Downloading Xray...")
    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        # Add headers to avoid potential rate limiting from GitHub API
        headers = {'Accept': 'application/vnd.github.v3+json'}
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        release_info = response.json()
        tag_name = release_info['tag_name']
        print(f"Latest Xray version tag: {tag_name}")

        system = platform.system().lower()
        machine = platform.machine().lower()
        asset_name = "Xray-linux-64.zip"
        if system == 'linux' and machine == 'aarch64':
             asset_name = "Xray-linux-arm64-v8a.zip"

        asset_url = None
        for asset in release_info['assets']:
            if asset['name'] == asset_name:
                asset_url = asset['browser_download_url']
                break
        if not asset_url: raise ValueError(f"Could not find asset '{asset_name}' in release {tag_name}")

        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=90)
        download_response.raise_for_status()

        print("Extracting Xray...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray'
                extracted = False
                for member in zf.namelist():
                    if member.endswith(exe_name) and not member.startswith('__MACOSX'):
                        # Ensure target path is clear before extraction/rename
                        if os.path.exists(XRAY_PATH):
                            print(f"Removing existing file at target path: {XRAY_PATH}")
                            os.remove(XRAY_PATH)

                        zf.extract(member, path=".")
                        extracted_path = os.path.join(".", member)
                        target_path = XRAY_PATH # Should be './xray'

                        if os.path.dirname(member): # If extracted into a subfolder
                            print(f"Moving extracted file from {extracted_path} to {target_path}")
                            os.rename(extracted_path, target_path)
                            try:
                                os.rmdir(os.path.join(".", os.path.dirname(member)))
                            except OSError: pass # Ignore if dir not empty
                        elif extracted_path != target_path: # If extracted to root but needs rename
                             print(f"Renaming extracted file from {extracted_path} to {target_path}")
                             os.rename(extracted_path, target_path)
                        # If extracted directly with correct name, it should already be at target_path

                        print(f"Extracted '{member}' successfully to '{target_path}'")
                        extracted = True
                        break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' not found within the zip file {asset_name}.")
        else:
            raise NotImplementedError(f"Extraction not implemented for {asset_name}")

        # --- Verification and Debugging Code ---
        if not os.path.exists(XRAY_PATH):
             raise FileNotFoundError(f"Xray executable not found at expected path '{XRAY_PATH}' after extraction attempt.")

        # Make executable
        if system != 'windows':
            try:
                st = os.stat(XRAY_PATH)
                os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
                print(f"Made '{XRAY_PATH}' executable.")
            except Exception as chmod_e:
                 print(f"ERROR: Failed to make '{XRAY_PATH}' executable: {chmod_e}")
                 return False # Cannot proceed if not executable

        # *** Insert Debugging Code Here (Correctly Indented) ***
        print(f"Attempting to verify {XRAY_PATH}...")
        try:
            # Check version
            version_cmd = [XRAY_PATH, "version"]
            version_process = subprocess.run(version_cmd, capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY VERSION ---")
            print(f"Exit Code: {version_process.returncode}")
            print(f"Stdout: {version_process.stdout.strip()}")
            print(f"Stderr: {version_process.stderr.strip()}")
            print(f"--- END XRAY VERSION ---")

            # Check help output for 'test' command
            help_cmd = [XRAY_PATH, "help"]
            help_process = subprocess.run(help_cmd, capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY HELP (searching for 'test' command) ---")
            help_output = help_process.stdout + help_process.stderr # Combine both streams for search
            if 'test' in help_output: # Check if 'test' appears anywhere
                print("  'test' command seems to be mentioned in help output.")
            else:
                print("  'test' command NOT found in help output.")
            # print(f"Help Combined Output:\n{help_output.strip()}") # Uncomment for full help
            print(f"--- END XRAY HELP ---")

        except Exception as verify_e:
            print(f"ERROR: Could not run Xray for verification: {verify_e}")
            return False # Indicate failure if verification fails

        print("Xray download and extraction complete.")
        return True # Success

    except Exception as e:
        print(f"Error in download_and_extract_xray function: {e}")
        # Check if binary exists despite error
        if os.path.exists(XRAY_PATH) and os.access(XRAY_PATH, os.X_OK):
            print("Using existing Xray binary despite error during download/extract attempt.")
            return True # Allow proceeding with existing binary if executable
        return False # Failed


# --- Enhanced V2Ray Config Generation ---
def generate_config(key_url):
    """Generates a minimal Xray JSON config for testing various key types."""
    # ... (Keep the enhanced generate_config function from the previous answer) ...
    # (Code that handles vmess, vless, trojan, ss is assumed here)
    try:
        key_url = key_url.strip()
        parsed_url = urlparse(key_url)
        protocol = parsed_url.scheme
        config = None
        base_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]
        }
        # ... (Include the full parsing logic for vmess, vless, trojan, ss from previous answer here) ...
        if protocol == "vmess":
            try:
                vmess_json_str = base64.b64decode(key_url[8:]).decode('utf-8')
                vmess_params = json.loads(vmess_json_str)
                base_config["outbounds"][0]["settings"]["vnext"] = [{"address": vmess_params.get("add", ""), "port": int(vmess_params.get("port", 443)), "users": [{"id": vmess_params.get("id", ""), "alterId": int(vmess_params.get("aid", 0)), "security": vmess_params.get("scy", "auto")}]}]
                stream_settings = {"network": vmess_params.get("net", "tcp"), "security": vmess_params.get("tls", "none")}
                if stream_settings["security"] == "tls": stream_settings["tlsSettings"] = {"serverName": vmess_params.get("sni", vmess_params.get("host", "")), "allowInsecure": False}
                net_type = stream_settings["network"]
                if net_type == "ws": stream_settings["wsSettings"] = {"path": vmess_params.get("path", "/"), "headers": {"Host": vmess_params.get("host", vmess_params.get("add", ""))}}
                elif net_type == "tcp" and vmess_params.get("type") == "http": stream_settings["tcpSettings"] = {"header": {"type": "http", "request": {"path": [vmess_params.get("path", "/")], "headers": {"Host": vmess_params.get("host", "").split(',')}}}}
                base_config["outbounds"][0]["streamSettings"] = stream_settings
                config = base_config
            except Exception: return None
        elif protocol == "vless":
            try:
                uuid = parsed_url.username; address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                base_config["outbounds"][0]["settings"]["vnext"] = [{"address": address, "port": port, "users": [{"id": uuid, "flow": params.get('flow', [None])[0] or ""}]}]
                stream_settings = {"network": params.get('type', ['tcp'])[0], "security": params.get('security', ['none'])[0]}
                sec_type = stream_settings["security"]
                if sec_type == "tls": stream_settings["tlsSettings"] = {"serverName": params.get('sni', [params.get('peer', [address])[0]])[0], "fingerprint": params.get('fp', [''])[0], "allowInsecure": False}
                elif sec_type == "reality": stream_settings["realitySettings"] = {"serverName": params.get('sni', [params.get('peer', [address])[0]])[0], "fingerprint": params.get('fp', [''])[0], "shortId": params.get('sid', [''])[0], "publicKey": params.get('pbk', [''])[0], "spiderX": params.get('spx', ['/'])[0]}
                net_type = stream_settings["network"]
                if net_type == "ws": stream_settings["wsSettings"] = {"path": unquote_plus(params.get('path', ['/'])[0]), "headers": {"Host": params.get('host', [address])[0]}}
                elif net_type == "grpc": stream_settings["grpcSettings"] = {"serviceName": unquote_plus(params.get('serviceName', [''])[0])}
                base_config["outbounds"][0]["streamSettings"] = stream_settings
                config = base_config
            except Exception: return None
        elif protocol == "trojan":
            try:
                password = parsed_url.username; address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                base_config["outbounds"][0]["settings"]["servers"] = [{"address": address, "port": port, "password": password}]
                stream_settings = {"network": params.get('type', ['tcp'])[0], "security": params.get('security', ['tls'])[0]}
                if stream_settings["security"] == "tls": stream_settings["tlsSettings"] = {"serverName": params.get('sni', [params.get('peer', [address])[0]])[0], "fingerprint": params.get('fp', [''])[0], "allowInsecure": False}
                net_type = stream_settings["network"]
                if net_type == "ws": stream_settings["wsSettings"] = {"path": unquote_plus(params.get('path', ['/'])[0]), "headers": {"Host": params.get('host', [address])[0]}}
                base_config["outbounds"][0]["streamSettings"] = stream_settings
                config = base_config
            except Exception: return None
        elif protocol == "ss":
             try:
                 user_info_part = parsed_url.netloc.split('@')[0]; server_part = parsed_url.netloc.split('@')[1]
                 address = server_part.split(':')[0]; port = int(server_part.split(':')[1])
                 decoded_user_info = ""; padding = '=' * (-len(user_info_part) % 4)
                 try: decoded_user_info = base64.b64decode(user_info_part + padding).decode('utf-8')
                 except Exception: decoded_user_info = unquote_plus(user_info_part)
                 method, password = decoded_user_info.split(':', 1)
                 base_config["outbounds"][0]["settings"]["servers"] = [{"address": address, "port": port, "method": method, "password": password}]
                 base_config["outbounds"][0]["streamSettings"]["network"] = "tcp"
                 config = base_config
             except Exception: return None
        else: return None
        if not config["outbounds"][0]["streamSettings"]: del config["outbounds"][0]["streamSettings"]
        return json.dumps(config, indent=2) if config else None
    except Exception: return None


# --- Key Testing Function with Added Debug Logging ---
def test_v2ray_key(key_url):
    """Tests a single V2Ray key using xray -test and logs failures."""
    config_json = generate_config(key_url)
    if not config_json:
        # print(f"DEBUG: Skipping test for {key_url[:50]}... (Config generation failed)")
        return key_url, False # Return False if config fails

    temp_config_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tf:
            tf.write(config_json)
            temp_config_file = tf.name

        # ***** TRY BOTH COMMAND FORMATS *****
        command_formats = [
            [XRAY_PATH, "test", "-config", temp_config_file],
            [XRAY_PATH, "run", "-test", "-config", temp_config_file]
        ]

        is_working = False
        process_stderr = "Unknown test error" # Default error
        process_returncode = -1 # Default error code

        for command in command_formats:
            # print(f"DEBUG: Attempting command: {' '.join(command)}") # Optional: Log command try
            try:
                process = subprocess.run(
                    command,
                    capture_output=True, text=True, timeout=TEST_TIMEOUT,
                    check=False, encoding='utf-8', errors='replace'
                )
                process_stderr = process.stderr.strip()
                process_returncode = process.returncode

                # Check for "unknown command" specifically for the first format
                if command[1] == "test" and "unknown command" in process_stderr.lower():
                    # print(f"DEBUG: 'xray test' failed with unknown command, trying 'xray run -test'...")
                    continue # Try the next command format

                is_working = process.returncode == 0
                if is_working:
                    # print(f"DEBUG: [OK] Key: {key_url[:70]}... with command {' '.join(command)}")
                    break # Stop trying commands if one works

            except subprocess.TimeoutExpired:
                process_stderr = f"Timeout ({TEST_TIMEOUT}s)"
                print(f"DEBUG: [FAIL] {process_stderr} for key: {key_url[:70]}...")
                is_working = False
                break # Timeout likely means connection failed, no need to try other cmd format
            except Exception as e:
                process_stderr = f"Subprocess execution error: {e}"
                print(f"DEBUG: [FAIL] {process_stderr} testing key {key_url[:70]}...")
                is_working = False
                # Might want to break here too, or let it try the other command if it was an execution error
                break

        # Log failure details if neither command format worked
        if not is_working:
            print(f"DEBUG: [FAIL] Key: {key_url[:70]}...")
            print(f"DEBUG:   Final Exit Code: {process_returncode}")
            if process_stderr:
                print(f"DEBUG:   Final Stderr: {process_stderr}")

        return key_url, is_working

    except Exception as e: # Catch errors in tempfile creation etc.
        print(f"DEBUG: [FAIL] Outer Error testing key {key_url[:70]}...: {e}")
        return key_url, False
    finally:
        if temp_config_file and os.path.exists(temp_config_file):
            try: os.remove(temp_config_file)
            except Exception as e_rem: print(f"Warning: Failed to remove temp config file {temp_config_file}: {e_rem}")


# --- Main Execution ---
def main():
    # ... (Keep the main function logic: start_time, download_and_extract_xray check, etc.) ...
    start_time = time.time(); print("Starting V2Ray Key Testing Script...")
    if not download_and_extract_xray(): print("FATAL: Failed to get/verify Xray binary. Aborting."); return
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK): print(f"FATAL: Xray executable not found or not executable at {XRAY_PATH}. Aborting."); return
    print(f"Using Xray executable at: {os.path.abspath(XRAY_PATH)}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    all_keys_to_test = []; source_map = {}
    print("\n--- Fetching Keys ---")
    # ... (Keep the fetching logic with Base64 handling) ...
    for command, url in SOURCE_URLS.items():
        keys_from_source = []
        try:
            print(f"Fetching {command} from {url}...")
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            raw_data = response.text; processed_data = raw_data
            try:
                potential_b64 = raw_data.replace('\n', '').replace('\r', '').strip()
                if len(potential_b64) > 20 and len(potential_b64) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in potential_b64):
                    decoded_bytes = base64.b64decode(potential_b64)
                    decoded_string = decoded_bytes.decode('utf-8')
                    if any(prefix in decoded_string for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
                        print(f"  Detected Base64 content for {command}, using decoded data.")
                        processed_data = decoded_string
                    else: print(f"  Decoded Base64 for {command} doesn't look like keys, treating as plain text.")
                else: print(f"  Content for {command} doesn't look like Base64 or is too short, treating as plain text.")
            except Exception as decode_error: print(f"  Base64 decoding failed for {command} (Error: {decode_error}), treating as plain text.")
            keys_from_source = [ line.strip() for line in processed_data.splitlines() if line.strip() and any(line.strip().startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"]) ]
            print(f"  Found {len(keys_from_source)} potential keys for {command} after processing.")
            for key in keys_from_source: all_keys_to_test.append(key); source_map[key] = command
        except requests.exceptions.RequestException as e: print(f"ERROR: Failed to fetch keys for {command} from {url}: {e}")
        except Exception as e: print(f"ERROR: Failed to process source {command} from {url}: {e}")

    print(f"\nTotal potential keys to test: {len(all_keys_to_test)}")
    if not all_keys_to_test:
         print("No keys fetched or extracted, nothing to test.")
         for command in SOURCE_URLS.keys():
             output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
             try: open(output_filename, 'w').close()
             except Exception as e_f: print(f"Warning: Could not create empty file {output_filename}: {e_f}")
         print("Created empty output files (if possible).")
         return

    # ... (Keep the parallel testing logic, results summary, file saving) ...
    working_keys_by_command = {cmd: [] for cmd in SOURCE_URLS.keys()}
    tested_count = 0; start_test_time = time.time()
    print(f"\n--- Starting Tests (Workers: {MAX_WORKERS}, Timeout: {TEST_TIMEOUT}s) ---")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in all_keys_to_test}
        for future in as_completed(future_to_key):
            key = future_to_key[future]; command_source = source_map.get(key); tested_count += 1
            try:
                _, is_working = future.result()
                if is_working and command_source: working_keys_by_command[command_source].append(key)
            except Exception as e_res: print(f"Warning: Error getting result for key {key[:40]}...: {e_res}"); pass
            if tested_count % 200 == 0 or tested_count == len(all_keys_to_test):
                elapsed = time.time() - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
                print(f"Progress: Tested {tested_count}/{len(all_keys_to_test)} keys... ({elapsed:.1f}s, {rate:.1f} keys/s)")
    print("\n--- Test Results Summary ---")
    total_working = 0
    for command, keys in working_keys_by_command.items():
        if command in { v for k, v in source_map.items() if v is not None}:
             print(f"  {command}: {len(keys)} working keys found.")
             total_working += len(keys); output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
             try:
                 keys.sort();
                 with open(output_filename, 'w', encoding='utf-8') as f:
                     for key in keys: f.write(key + '\n')
             except Exception as e_w: print(f"    ERROR writing file {output_filename}: {e_w}")
    for command in SOURCE_URLS.keys():
         output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
         if not os.path.exists(output_filename):
              try: open(output_filename, 'w').close(); print(f"  {command}: 0 working keys found (created empty file).")
              except Exception as e_f: print(f"Warning: Could not create empty file {output_filename}: {e_f}")
    end_time = time.time()
    print(f"\nTotal working keys found and saved across all sources: {total_working}")
    print(f"Script finished in {end_time - start_time:.2f} seconds.")
    print("----------------------------------------")


if __name__ == "__main__":
    main()
