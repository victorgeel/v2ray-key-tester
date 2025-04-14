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
    # ဒီနေရာမှာ သင် နောက်ဆုံး စမ်းသပ်ခဲ့တဲ့ URL configuration ကို ထားပါ
    # ဥပမာ - မူလအတိုင်း ပြန်ထားချင်ရင် အရင်က URL တွေကို ပြန်ထည့်ပါ
    # ဒါမှမဟုတ် စမ်းသပ်တုန်းကအတိုင်း key5 မှာ us link, key6 မှာ key1 link ထားထားတာလည်း ဖြစ်နိုင်ပါတယ်
    # သင့် လက်ရှိ configuration အတိုင်း ထားခဲ့ပါ၊ ဒီ script က ပြဿနာရှာဖို့ log ထုတ်ပါလိမ့်မယ်
    "key1": "https://raw.githubusercontent.com/darknessm427/V2ray-Sub-Collector/main/Sort-By-Protocol/Darkness_vmess.txt",
    "key2": "https://raw.githubusercontent.com/SonzaiEkkusu/V2RayDumper/main/config.txt",
    "key3": "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "key6": "https://raw.githubusercontent.com/darknessm427/V2ray-Sub-Collector/main/Sort-By-Protocol/Darkness_vmess.txt", # For testing
    "key5": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt", # For testing
    "key4": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
    "hk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Hong_Kong.txt",
    "jp": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Japan.txt",
    "sg": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Singapore.txt",
    "us": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "tw": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "uk": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_Kingdom.txt",
}

OUTPUT_DIR = "output"
XRAY_PATH = "./xray"
# --- DEBUGGING: Set workers to 1 to disable concurrency ---
MAX_WORKERS = 1
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 20 # Increase if needed, especially with worker=1

# --- Xray Installation ---
def download_and_extract_xray():
    # ... (ဒီ function က မပြောင်းပါ - keep as is) ...
    """Downloads and extracts the latest Xray core binary using GitHub token."""
    print("Checking/Downloading Xray...")
    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        github_token = os.environ.get('GH_TOKEN')
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if github_token:
            # print("Using GitHub token for API request to avoid rate limits.") # Less verbose
            headers['Authorization'] = f'token {github_token}'
        else:
            print("Warning: GitHub token (GH_TOKEN) not found in environment. Making unauthenticated API request (may hit rate limits).")

        response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        release_info = response.json()
        tag_name = release_info['tag_name']
        print(f"Latest Xray version tag: {tag_name}")

        system = platform.system().lower(); machine = platform.machine().lower()
        asset_name = "Xray-linux-64.zip"
        if system == 'linux' and machine == 'aarch64': asset_name = "Xray-linux-arm64-v8a.zip"
        # Add windows support maybe later if needed
        # elif system == 'windows': asset_name = "Xray-windows-64.zip"
        asset_url = None
        for asset in release_info['assets']:
            if asset['name'] == asset_name: asset_url = asset['browser_download_url']; break
        if not asset_url: raise ValueError(f"Could not find asset '{asset_name}' for {system} {machine}")
        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=90); download_response.raise_for_status()

        print("Extracting Xray...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray.exe' if system == 'windows' else 'xray'
                extracted = False
                for member in zf.namelist():
                    # Handle cases where executable might be in a subdirectory
                    if member.endswith(exe_name) and not member.startswith('__MACOSX'):
                        if os.path.exists(XRAY_PATH): os.remove(XRAY_PATH) # Remove old version first
                        zf.extract(member, path="."); # Extract to current dir
                        extracted_path = os.path.join(".", member) # Path where it was extracted
                        target_path = XRAY_PATH # Desired final path

                        # Move if extracted to a subdirectory or needs renaming
                        if os.path.dirname(member) or extracted_path != target_path:
                            print(f"Moving/Renaming extracted file from {extracted_path} to {target_path}")
                            os.rename(extracted_path, target_path)
                            # Attempt to remove the directory it came from if it's now empty
                            if os.path.dirname(member):
                                try:
                                    os.rmdir(os.path.join(".", os.path.dirname(member)))
                                    print(f"Removed empty source directory: {os.path.dirname(member)}")
                                except OSError:
                                    # Directory might not be empty or other issue, ignore
                                    print(f"Could not remove source directory (might not be empty): {os.path.dirname(member)}")
                                    pass
                        print(f"Extracted '{member}' successfully to '{target_path}'"); extracted = True; break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' not found within the zip file {asset_name}.")
        # Add tar.gz support if needed later
        # elif asset_name.endswith(".tar.gz"):
        #     # Add tar.gz extraction logic here
        #     raise NotImplementedError(f"Extraction not implemented for {asset_name}")
        else: raise NotImplementedError(f"Extraction not implemented for {asset_name}")

        if not os.path.exists(XRAY_PATH): raise FileNotFoundError(f"Xray executable not found at '{XRAY_PATH}' after extraction.")

        # Make executable on non-windows
        if system != 'windows':
            try:
                st = os.stat(XRAY_PATH)
                os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
                print(f"Made '{XRAY_PATH}' executable.")
            except Exception as chmod_e:
                print(f"ERROR: Failed to make '{XRAY_PATH}' executable: {chmod_e}")
                return False # Cannot proceed if not executable

        # --- Verification ---
        print(f"Attempting to verify {XRAY_PATH}...")
        try:
            version_cmd = [XRAY_PATH, "version"]
            # Use absolute path for robustness
            # version_cmd = [os.path.abspath(XRAY_PATH), "version"]
            version_process = subprocess.run(version_cmd, capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY VERSION ---"); print(f"Exit Code: {version_process.returncode}"); print(f"Stdout: {version_process.stdout.strip()}"); print(f"Stderr: {version_process.stderr.strip()}"); print(f"--- END XRAY VERSION ---")
            if version_process.returncode != 0:
                 print("Warning: Xray version command failed!")
                 # Consider returning False if version check is critical
                 # return False

            # Check for 'test' command availability in help output
            help_cmd = [XRAY_PATH, "help"]
            help_process = subprocess.run(help_cmd, capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY HELP (searching for 'test' command) ---");
            help_output = help_process.stdout + help_process.stderr
            if ' test ' in help_output: # Check for ' test ' with spaces to be more specific
                print("  'test' command seems to be available in help output.")
            else:
                print("  Warning: 'test' command NOT found explicitly in help output. Relying on 'run -test'.")
            print(f"--- END XRAY HELP ---")

        except Exception as verify_e:
            print(f"ERROR: Could not run Xray for verification: {verify_e}")
            return False

        print("Xray download and extraction complete.")
        return True # Success

    except requests.exceptions.RequestException as req_e:
        print(f"ERROR: Failed GitHub API request: {req_e}")
        return False
    except Exception as e:
        print(f"Error in download_and_extract_xray function: {e}")
        return False


# --- Config Generation (generate_config) ---
def generate_config(key_url):
    # ... (ဒီ function က မပြောင်းပါ - keep as is) ...
    """Generates a minimal Xray JSON config for testing various key types."""
    try:
        key_url = key_url.strip()
        if not key_url or '://' not in key_url:
            # print(f"DEBUG: Invalid key URL format: {key_url[:50]}")
            return None
        parsed_url = urlparse(key_url)
        protocol = parsed_url.scheme
        config = None

        # Base structure
        base_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]
        }

        outbound = base_config["outbounds"][0] # Easier reference

        if protocol == "vmess":
            try:
                # Handle potential padding errors during decode
                try:
                    # Remove the vmess:// part and decode
                    vmess_b64 = key_url[8:]
                    # Add padding if necessary
                    vmess_b64 += '=' * (-len(vmess_b64) % 4)
                    vmess_json_str = base64.b64decode(vmess_b64).decode('utf-8')
                    vmess_params = json.loads(vmess_json_str)
                except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as decode_e:
                    # print(f"DEBUG: Failed to decode/parse VMess JSON for {key_url[:50]}: {decode_e}")
                    return None

                # Populate settings
                outbound["settings"]["vnext"] = [{
                    "address": vmess_params.get("add", ""),
                    "port": int(vmess_params.get("port", 443)), # Ensure port is int
                    "users": [{
                        "id": vmess_params.get("id", ""),
                        "alterId": int(vmess_params.get("aid", 0)), # Ensure aid is int
                        "security": vmess_params.get("scy", "auto")
                    }]
                }]

                # Populate streamSettings
                stream_settings = {
                    "network": vmess_params.get("net", "tcp"),
                    "security": vmess_params.get("tls", "none")
                }
                if stream_settings["security"] == "tls":
                    sni = vmess_params.get("sni", vmess_params.get("host", "")) # Use sni first, fallback to host
                    if not sni: sni = vmess_params.get("add", "") # Fallback to address if host/sni empty
                    stream_settings["tlsSettings"] = {
                        "serverName": sni,
                        "allowInsecure": False # Usually should be False
                        # Add fingerprint if needed: "fingerprint": vmess_params.get("fp", "")
                    }

                net_type = stream_settings["network"]
                host = vmess_params.get("host", vmess_params.get("add", "")) # Use host first, fallback to address
                path = vmess_params.get("path", "/")

                if net_type == "ws":
                    stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "tcp" and vmess_params.get("type") == "http":
                    # Handle potential comma in host for http header type
                    host_list = [h.strip() for h in host.split(',') if h.strip()]
                    if not host_list: host_list = [vmess_params.get("add", "")] # Fallback if host is empty/invalid
                    stream_settings["tcpSettings"] = {
                        "header": {
                            "type": "http",
                            "request": {
                                "path": [path], # Path should be a list
                                "headers": {"Host": host_list}
                            }
                        }
                    }
                # Add other network types like h2, grpc, quic if needed

                outbound["streamSettings"] = stream_settings
                config = base_config

            except Exception as e:
                # print(f"DEBUG: Error processing VMess key {key_url[:50]}: {e}")
                return None # Fail gracefully if any part fails

        elif protocol == "vless":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None # Basic check
                uuid = parsed_url.username
                address = parsed_url.hostname
                port = int(parsed_url.port or 443)
                params = parse_qs(parsed_url.query)

                # Populate settings
                outbound["settings"]["vnext"] = [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "flow": params.get('flow', [None])[0] or "" # Use flow if present
                        # Add encryption type if needed, usually "none" for VLESS
                        # "encryption": params.get('encryption', ['none'])[0]
                    }]
                }]

                # Populate streamSettings
                stream_settings = {
                    "network": params.get('type', ['tcp'])[0],
                    "security": params.get('security', ['none'])[0]
                }
                sec_type = stream_settings["security"]
                sni = params.get('sni', [params.get('peer', [address])[0]])[0] # Use sni, fallback peer, fallback address
                fingerprint = params.get('fp', [''])[0]

                if sec_type == "tls":
                    stream_settings["tlsSettings"] = {
                        "serverName": sni,
                        "fingerprint": fingerprint,
                        "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1' # Allow insecure if specified
                        # Add alpn if needed: "alpn": params.get('alpn', ['h2,http/1.1'])[0].split(',')
                    }
                elif sec_type == "reality":
                    pbk = params.get('pbk', [''])[0]
                    sid = params.get('sid', [''])[0]
                    spx = params.get('spx', ['/'])[0]
                    if not pbk: return None # Public key is mandatory for reality
                    stream_settings["realitySettings"] = {
                        "serverName": sni, # Usually the same as sni in realitySettings
                        "fingerprint": fingerprint,
                        "shortId": sid,
                        "publicKey": pbk,
                        "spiderX": spx
                    }

                net_type = stream_settings["network"]
                host = params.get('host', [address])[0] # Use host param, fallback address
                path = unquote_plus(params.get('path', ['/'])[0])
                service_name = unquote_plus(params.get('serviceName', [''])[0])

                if net_type == "ws":
                    stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc":
                     # Ensure serviceName is provided for gRPC
                    if not service_name: return None
                    stream_settings["grpcSettings"] = {"serviceName": service_name}
                # Add other network types if needed

                outbound["streamSettings"] = stream_settings
                config = base_config

            except Exception as e:
                # print(f"DEBUG: Error processing VLESS key {key_url[:50]}: {e}")
                return None

        elif protocol == "trojan":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None # Basic check
                password = unquote_plus(parsed_url.username) # Password might be URL encoded
                address = parsed_url.hostname
                port = int(parsed_url.port or 443)
                params = parse_qs(parsed_url.query)

                # Populate settings
                outbound["settings"]["servers"] = [{
                    "address": address,
                    "port": port,
                    "password": password
                }]

                # Populate streamSettings
                # Trojan defaults to 'tls' security if 'security' param is missing
                stream_settings = {
                    "network": params.get('type', ['tcp'])[0],
                    "security": params.get('security', ['tls'])[0]
                }
                sni = params.get('sni', [params.get('peer', [address])[0]])[0] # Use sni, fallback peer, fallback address
                fingerprint = params.get('fp', [''])[0]

                # Only add tlsSettings if security is actually tls
                if stream_settings["security"] == "tls":
                     stream_settings["tlsSettings"] = {
                         "serverName": sni,
                         "fingerprint": fingerprint,
                         "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1'
                         # Add alpn if needed
                     }
                elif stream_settings["security"] != 'none':
                     # Handle potential other security types if necessary, otherwise ignore unknown ones
                     pass

                net_type = stream_settings["network"]
                host = params.get('host', [address])[0]
                path = unquote_plus(params.get('path', ['/'])[0])
                service_name = unquote_plus(params.get('serviceName', [''])[0]) # For grpc

                if net_type == "ws":
                    stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc":
                    if not service_name: return None # Required for grpc
                    stream_settings["grpcSettings"] = {"serviceName": service_name}
                # Add other network types

                outbound["streamSettings"] = stream_settings
                config = base_config

            except Exception as e:
                # print(f"DEBUG: Error processing Trojan key {key_url[:50]}: {e}")
                return None

        elif protocol == "ss":
             try:
                 # ss://method:password@server:port#remark
                 # ss://BASE64_METHOD_PASS@server:port#remark (Base64 includes method:pass)
                 if '@' not in parsed_url.netloc: return None

                 user_info_part = parsed_url.netloc.split('@')[0]
                 server_part = parsed_url.netloc.split('@')[1]

                 if ':' not in server_part: return None
                 address = server_part.split(':')[0]
                 port = int(server_part.split(':')[1])

                 method = None
                 password = None

                 # Try decoding Base64 first (common format)
                 decoded_user_info = None
                 try:
                     # Add padding if necessary
                     user_info_b64 = user_info_part
                     user_info_b64 += '=' * (-len(user_info_b64) % 4)
                     decoded_user_info = base64.b64decode(user_info_b64).decode('utf-8')
                 except Exception:
                     # If decode fails, assume plain text method:password
                     decoded_user_info = unquote_plus(user_info_part)

                 if ':' not in decoded_user_info:
                     # print(f"DEBUG: Decoded SS user info lacks colon separator: {decoded_user_info}")
                     return None # Must have method:password format
                 method, password = decoded_user_info.split(':', 1)

                 # Populate settings
                 outbound["settings"]["servers"] = [{
                     "address": address,
                     "port": port,
                     "method": method,
                     "password": password
                 }]
                 # SS generally uses TCP, stream settings usually not needed unless using plugins (e.g., v2ray-plugin)
                 # We'll assume simple TCP for testing
                 outbound["streamSettings"]["network"] = "tcp"
                 # Remove security field for SS as it's defined by method/password
                 if "security" in outbound["streamSettings"]:
                     del outbound["streamSettings"]["security"]

                 config = base_config

             except Exception as e:
                 # print(f"DEBUG: Error processing SS key {key_url[:50]}: {e}")
                 return None

        else:
            # print(f"DEBUG: Unsupported protocol: {protocol}")
            return None # Unsupported protocol

        # Clean up empty streamSettings if no relevant options were added
        if "streamSettings" in outbound and not outbound["streamSettings"]:
            del outbound["streamSettings"]
        elif "streamSettings" in outbound:
             # Clean up specific empty settings within streamSettings if needed
             if "tlsSettings" in outbound["streamSettings"] and not outbound["streamSettings"]["tlsSettings"]: del outbound["streamSettings"]["tlsSettings"]
             if "wsSettings" in outbound["streamSettings"] and not outbound["streamSettings"]["wsSettings"]: del outbound["streamSettings"]["wsSettings"]
             # etc. for other settings types

        return json.dumps(config, indent=2) if config else None
    except Exception as e:
        # Catch any other unexpected error during generation
        # print(f"DEBUG: Unexpected error in generate_config for {key_url[:50]}: {e}")
        return None


# --- Key Testing (test_v2ray_key) ---
def test_v2ray_key(key_url):
    """Tests a single V2Ray key using xray -test and logs failures."""
    config_json = generate_config(key_url)
    if not config_json:
        # print(f"DEBUG: Skipping test for {key_url[:50]}... (Config generation failed)")
        return key_url, False

    temp_config_file = None
    try:
        # Create temp file with UTF-8 encoding explicitly
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tf:
            tf.write(config_json)
            temp_config_file = tf.name
            # print(f"DEBUG: Temp config file created at {temp_config_file} for key {key_url[:50]}")

        # Prefer `xray run -test` as `xray test` might be deprecated/less reliable
        command_formats = [
            [XRAY_PATH, "run", "-test", "-config", temp_config_file]
            # [XRAY_PATH, "test", "-config", temp_config_file], # Fallback if needed
        ]
        is_working = False; process_stderr = "Unknown test error"; process_returncode = -1

        for command in command_formats:
            # print(f"DEBUG: Running command: {' '.join(command)}")
            try:
                process = subprocess.run(
                    command, capture_output=True, text=True, timeout=TEST_TIMEOUT,
                    check=False, encoding='utf-8', errors='replace' # Use errors='replace' for safety
                )
                process_stderr = process.stderr.strip(); process_returncode = process.returncode

                # `xray run -test` should exit with 0 on success
                is_working = process.returncode == 0

                # Specific check for common failure indicators even if exit code is 0 (sometimes happens)
                if is_working and process_stderr:
                     # Add keywords that indicate failure despite exit code 0
                     failure_keywords = ["failed to dial", "proxy connection failed", "timeout"]
                     if any(keyword in process_stderr.lower() for keyword in failure_keywords):
                          print(f"DEBUG: [WARN] Exit code 0 but stderr indicates failure for {key_url[:70]}... Stderr: {process_stderr}")
                          is_working = False # Treat as failure

                if is_working:
                    # print(f"DEBUG: Command {' '.join(command)} succeeded.")
                    break # Stop testing if a command format works
                # else:
                #     print(f"DEBUG: Command {' '.join(command)} failed with code {process_returncode}.")
                #     if process_stderr: print(f"DEBUG:   Stderr: {process_stderr}")


            except subprocess.TimeoutExpired:
                process_stderr = f"Timeout ({TEST_TIMEOUT}s)"; print(f"DEBUG: [FAIL] {process_stderr} for key: {key_url[:70]}..."); is_working = False; break # Timeout means failure
            except Exception as e:
                process_stderr = f"Subprocess execution error: {e}"; print(f"DEBUG: [FAIL] {process_stderr} testing key {key_url[:70]}..."); is_working = False; break # Other execution error

        # Final logging based on outcome
        if not is_working:
            print(f"DEBUG: [FAIL] Key: {key_url[:70]}...")
            # Only print final code/stderr if it wasn't already logged as Timeout/Exec error
            if "Timeout" not in process_stderr and "Subprocess execution error" not in process_stderr:
                 print(f"DEBUG:   Final Exit Code: {process_returncode}")
                 if process_stderr: print(f"DEBUG:   Final Stderr: {process_stderr}")
        # else:
        #      print(f"DEBUG: [OK] Key: {key_url[:70]}...") # Uncomment to log successes too

        return key_url, is_working

    except Exception as e:
        # Catch errors related to temp file creation or other outer issues
        print(f"DEBUG: [FAIL] Outer Error in test_v2ray_key for {key_url[:70]}...: {e}")
        return key_url, False
    finally:
        # Ensure temp file removal
        if temp_config_file and os.path.exists(temp_config_file):
            try:
                os.remove(temp_config_file)
                # print(f"DEBUG: Removed temp config file {temp_config_file}")
            except Exception as e_rem:
                print(f"Warning: Failed to remove temp config file {temp_config_file}: {e_rem}")


# --- Main Execution (main) ---
def main():
    start_time = time.time(); print("Starting V2Ray Key Testing Script...")
    if not download_and_extract_xray(): print("FATAL: Failed to get/verify Xray binary. Aborting."); return
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK): print(f"FATAL: Xray executable not found or not executable at {XRAY_PATH}. Aborting."); return
    print(f"Using Xray executable at: {os.path.abspath(XRAY_PATH)}")
    os.makedirs(OUTPUT_DIR, exist_ok=True); all_keys_to_test = []; source_map = {}
    print("\n--- Fetching Keys ---")
    for command, url in SOURCE_URLS.items():
        keys_from_source = []
        try:
            print(f"Fetching {command} from {url}...")
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0 V2RayKeyTester/1.0'}) # Add a specific user agent
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Attempt to decode using response encoding first, fallback to utf-8
            try:
                raw_data = response.content.decode(response.encoding or 'utf-8', errors='replace')
            except Exception:
                # Fallback if decoding fails completely
                raw_data = response.text # Let requests handle decoding as best it can

            processed_data = raw_data

            # Base64 detection and decoding logic
            try:
                # Basic check if it *might* be base64 encoded list
                potential_b64 = raw_data.replace('\n', '').replace('\r', '').strip()
                is_likely_b64_list = (len(potential_b64) > 20 and
                                      all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n ' for c in raw_data.strip())) # Allow whitespace in raw b64

                if is_likely_b64_list:
                    # Try decoding the whole block first, might be one large b64 string
                    decoded_string = ""
                    try:
                         # Ensure correct padding
                         potential_b64_padded = potential_b64 + '=' * (-len(potential_b64) % 4)
                         decoded_bytes = base64.b64decode(potential_b64_padded)
                         decoded_string = decoded_bytes.decode('utf-8', errors='replace')
                    except Exception:
                         decoded_string = "" # Reset if full block decode fails

                    # If decoded string contains protocols, assume it was a single B64 blob
                    if any(prefix in decoded_string for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
                        print(f"  Detected single Base64 block content for {command}, using decoded data.")
                        processed_data = decoded_string
                    else:
                        # Try decoding line by line if full block failed or didn't yield keys
                        print(f"  Content for {command} might be line-by-line Base64 or plain text.")
                        lines = raw_data.splitlines()
                        decoded_lines = []
                        possible_keys_found = False
                        for line in lines:
                            line = line.strip()
                            if not line: continue
                            if any(line.startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"]):
                                 # If line already looks like a key, add it directly
                                 decoded_lines.append(line)
                                 possible_keys_found = True
                            else:
                                 # Try decoding the line as Base64
                                 try:
                                     line_padded = line + '=' * (-len(line) % 4)
                                     d_bytes = base64.b64decode(line_padded)
                                     d_line = d_bytes.decode('utf-8', errors='replace')
                                     # Only add if the decoded line looks like a key
                                     if any(d_line.startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"]):
                                          decoded_lines.append(d_line)
                                          possible_keys_found = True
                                     # else: ignore decoded line if it doesn't look like a key
                                 except Exception:
                                     # Ignore lines that fail decoding or aren't keys
                                     pass
                        if possible_keys_found:
                             print(f"  Processed {command} as mixed/line-by-line Base64/plain text.")
                             processed_data = "\n".join(decoded_lines)
                        else:
                             print(f"  Content for {command} treated as plain text (no Base64 keys detected).")
                             processed_data = raw_data # Fallback to original if no keys found after trying decode

            except Exception as decode_error:
                print(f"  Error during Base64 check/decode for {command} (Error: {decode_error}), treating as plain text.")
                processed_data = raw_data # Fallback to original data

            # Final key extraction from processed_data
            keys_from_source = [
                line.strip() for line in processed_data.splitlines()
                if line.strip() and any(line.strip().startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"])
            ]

            print(f"  Found {len(keys_from_source)} potential keys for {command} after processing.")
            if keys_from_source: # Only map if keys were found
                for key in keys_from_source:
                    all_keys_to_test.append(key)
                    source_map[key] = command # Map the key back to its originating command label
            # else: print(f"  No valid keys found for {command} to add to test list.")

        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed to fetch keys for {command} from {url}: {e}")
        except Exception as e:
            print(f"ERROR: Failed to process source {command} from {url}: {e}")

    print(f"\nTotal potential keys to test across all sources: {len(all_keys_to_test)}")
    if not all_keys_to_test:
         print("No keys fetched or extracted, nothing to test.");
         # Create empty files even if no keys to test
         for command in SOURCE_URLS.keys():
             output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
             try:
                 # Ensure UTF-8 and LF even for empty files
                 with open(output_filename, 'w', encoding='utf-8', newline='\n') as f:
                     pass # Just create the file
                 print(f"  Created empty file: {output_filename}")
             except Exception as e_f:
                 print(f"Warning: Could not create empty file {output_filename}: {e_f}")
         print("Finished creating empty output files (if possible).")
         return # Exit if nothing to test

    # Use a set for faster lookup of keys processed for each command
    working_keys_by_command = {cmd: [] for cmd in SOURCE_URLS.keys()}
    tested_count = 0
    start_test_time = time.time()
    print(f"\n--- Starting Tests (Workers: {MAX_WORKERS}, Timeout: {TEST_TIMEOUT}s) ---")

    # Use ThreadPoolExecutor for parallel testing
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Map future object back to the original key URL for tracking
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in all_keys_to_test}

        for future in as_completed(future_to_key):
            key = future_to_key[future] # Get the key URL associated with this future
            command_source = source_map.get(key) # Find the original command source ('key1', 'hk', etc.)
            tested_count += 1

            try:
                # Get the result (original_key_url, is_working_status)
                _key_url_ignored, is_working = future.result()

                # --- DEBUG LOGGING ADDED ---
                if command_source in ['key1', 'key5']:
                    print(f"DEBUG: Result for source '{command_source}': Key = {key[:40]}..., Working = {is_working}")
                # --- DEBUG LOGGING ADDED ---

                # If the key worked AND we know its source command
                if is_working and command_source:
                    # --- DEBUG LOGGING ADDED ---
                    if command_source in ['key1', 'key5']:
                         print(f"DEBUG: Appending working key for '{command_source}' to results list.")
                    # --- DEBUG LOGGING ADDED ---
                    working_keys_by_command[command_source].append(key)

            except Exception as e_res:
                # Handle errors if getting the result from the future fails
                print(f"Warning: Error getting result for key {key[:40]}...: {e_res}")
                # --- DEBUG LOGGING ADDED ---
                if command_source in ['key1', 'key5']: # Log error specifically for these
                     print(f"DEBUG: Exception occurred while getting result for '{command_source}' key.")
                # --- DEBUG LOGGING ADDED ---
                pass # Continue to the next future

            # Print progress periodically
            if tested_count % 100 == 0 or tested_count == len(all_keys_to_test): # Adjust frequency if needed
                elapsed = time.time() - start_test_time
                rate = tested_count / elapsed if elapsed > 0 else 0
                print(f"Progress: Tested {tested_count}/{len(all_keys_to_test)} keys... ({elapsed:.1f}s, {rate:.1f} keys/s)")

    print("\n--- Test Results Summary ---")
    total_working = 0

    # Process results and write files
    processed_commands = set() # Keep track of commands for which files were written
    for command, keys in working_keys_by_command.items():
        # Only process if keys were actually tested for this command (i.e., source was fetched ok)
        # This check might be slightly inaccurate if fetch worked but yielded 0 keys that were mapped.
        # A better check might be `if command in { v for v in source_map.values()}` but less efficient.
        # We rely on the empty file creation logic later for commands with 0 keys.

        # Only proceed if there are keys OR if the command source was validly processed
        source_was_processed = command in { v for k, v in source_map.items() if v is not None}

        if keys or source_was_processed: # Write file if keys exist OR if the source was attempted
            num_keys = len(keys)
            print(f"  {command}: {num_keys} working keys found.")
            total_working += num_keys
            output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
            processed_commands.add(command) # Mark this command as processed

            try:
                keys.sort(); # Sort keys alphabetically before writing
                # --- DEBUG LOGGING ADDED ---
                if command in ['key1', 'key5']:
                    print(f"DEBUG: Preparing to write file for '{command}'. Keys found: {num_keys}. Filename: {output_filename}")
                # --- DEBUG LOGGING ADDED ---

                # --- Ensure UTF-8 and LF line endings using newline='\n' ---
                with open(output_filename, 'w', encoding='utf-8', newline='\n') as f:
                    for key_to_write in keys:
                        f.write(key_to_write + '\n')

                # --- DEBUG LOGGING ADDED ---
                if command in ['key1', 'key5']:
                    # Add a small delay and check if file exists and has size, maybe? Might be overkill.
                    if os.path.exists(output_filename):
                         print(f"DEBUG: Finished writing file for '{command}'. Size: {os.path.getsize(output_filename)} bytes.")
                    else:
                         print(f"DEBUG: ERROR - File {output_filename} NOT found after writing for '{command}'.")

            except Exception as e_w:
                print(f"    ERROR writing file {output_filename}: {e_w}")
                # --- DEBUG LOGGING ADDED ---
                if command in ['key1', 'key5']: # Log error specifically for these
                     print(f"DEBUG: Exception occurred while writing file for '{command}'.")
                # --- DEBUG LOGGING ADDED ---

    # Ensure empty files are created for any commands defined in SOURCE_URLS
    # but didn't end up with a written file (e.g., fetch failed, or 0 working keys found
    # AND the source_was_processed check above didn't catch it - this covers all bases)
    print("\n--- Ensuring output files exist for all sources ---")
    for command in SOURCE_URLS.keys():
         if command not in processed_commands:
              output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
              if not os.path.exists(output_filename): # Check again for safety
                  try:
                      # Ensure UTF-8 and LF even for empty files
                      with open(output_filename, 'w', encoding='utf-8', newline='\n') as f:
                          pass # Just create the empty file
                      print(f"  {command}: 0 working keys processed (created empty file: {output_filename}).")
                  except Exception as e_f:
                      print(f"Warning: Could not create empty file {output_filename}: {e_f}")

    end_time = time.time()
    print(f"\nTotal working keys found and saved across all sources: {total_working}")
    print(f"Script finished in {end_time - start_time:.2f} seconds.")
    print("----------------------------------------")

if __name__ == "__main__":
    main()
