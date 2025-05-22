import requests
import subprocess
import os
import json
import base64
import yaml
import time
import sys
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging # Use logging for better error handling and output control

# --- Configuration ---
# Use logging for output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Set a higher level for requests to reduce verbose output
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


DEFAULT_SOURCE_URLS = {
    "source1_ss": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",
    "source2_mix": "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mixbase64", # This one is often base64 encoded content
    "source3_vless": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt", # Check content format - might be mixed
    "source4_all": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "source5_us": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "source6_vmess": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY.txt", # Often contains vmess
}

# !!! IMPORTANT:
# V2RAY_BINARY should be the path to your V2Ray/Xray executable.
# Ensure this binary is available in the GitHub Actions runner environment.
# You will likely need a step in your workflow to download and make it executable.
V2RAY_BINARY = os.environ.get("V2RAY_BINARY_PATH", "./v2ray") # Default path, check env var or adjust

# V2RAY_TEMPLATE_CONFIG is the base V2Ray config JSON template.
# It MUST contain an inbound (e.g., socks on 127.0.0.1:1080) and a routing rule
# to direct traffic from that inbound to the outbound with tag "test_proxy_out".
V2RAY_TEMPLATE_CONFIG = "template.json" # Ensure this file exists

OUTPUT_DIR = "subscription"
WORKING_KEYS_FILE = os.path.join(OUTPUT_DIR, "working_subscription.txt")
CLASH_CONFIG_FILE = os.path.join(OUTPUT_DIR, "clash_config.yaml")

MAX_WORKERS = 25 # Increased concurrency for fetching and testing
REQUEST_TIMEOUT = 20 # Timeout for fetching subscription URLs
TEST_TIMEOUT_PER_KEY = 20 # Timeout for the entire test process for a single key (includes V2Ray startup and HTTP request)
PROXY_LISTEN_PORT = 1080 # The port the local V2Ray instance will listen on (must match template.json)
PROXY_PROTOCOL = "socks" # The protocol the local V2Ray instance will listen on (must match template.json - socks or http)
PROXY_TEST_URL = "http://www.gstatic.com/generate_204" # Reliable URL for testing connectivity
# PROXY_TEST_URL = "http://www.google.com/generate_204" # Alternative
# PROXY_TEST_URL = "http://cp.cloudflare.com/" # Another alternative

# --- Utility Functions ---

def get_source_urls_from_env():
    """Fetch subscription URLs from environment variables or use defaults."""
    urls_json = os.getenv("SUBSCRIPTION_URLS")
    if urls_json:
        try:
            # Expecting a JSON-formatted string like '{"name1": "url1", "name2": "url2"}'
            urls_dict = json.loads(urls_json)
             # Ensure keys are strings and values are strings
            if not isinstance(urls_dict, dict):
                 logging.error("SUBSCRIPTION_URLS environment variable is not a JSON object/dictionary.")
                 return DEFAULT_SOURCE_URLS
            validated_urls = {}
            for k, v in urls_dict.items():
                 if isinstance(k, str) and isinstance(v, str):
                      validated_urls[k] = v
                 else:
                     logging.warning(f"Skipping invalid entry in SUBSCRIPTION_URLS: {k}: {v} (Keys and values must be strings)")
            if validated_urls:
                 return validated_urls
            else:
                 logging.warning("SUBSCRIPTION_URLS environment variable was parsed, but contained no valid entries. Using default URLs.")
                 return DEFAULT_SOURCE_URLS

        except json.JSONDecodeError:
            logging.error("Error parsing SUBSCRIPTION_URLS from environment: Invalid JSON format. Using default URLs.")
            return DEFAULT_SOURCE_URLS
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing SUBSCRIPTION_URLS env var: {e}. Using default URLs.")
            return DEFAULT_SOURCE_URLS
    logging.info("SUBSCRIPTION_URLS environment variable not set or empty. Using default URLs.")
    return DEFAULT_SOURCE_URLS

def validate_subscription_url(url):
    """Validate the subscription URL format."""
    if not isinstance(url, str):
        return False
    try:
        result = urlparse(url)
        # Check for valid scheme (http, https) and netloc (domain/IP)
        return result.scheme in ["http", "https"] and bool(result.netloc)
    except Exception:
        # Invalid URL format
        return False

def decode_base64(data):
    """Decode base64 string, handling potential errors."""
    if not isinstance(data, str):
        return None
    try:
        # Attempt strict base64 decode first
        decoded_bytes = base64.b64decode(data, validate=True)
        return decoded_bytes.decode("utf-8")
    except (base64.binascii.Error, UnicodeDecodeError):
        # If strict decoding fails, try decoding ignoring errors (might be padded incorrectly or corrupt)
        try:
             decoded_bytes = base64.b64decode(data, validate=False) # Attempt without strict validation
             return decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
             return None # Still failed
    except Exception:
        return None # Catch any other exceptions during decoding

def fetch_subscription(url):
    """
    Fetches content from URL.
    Tries to decode as Base64 if it looks like Base64.
    Returns a list of lines (potential keys).
    Strictly skips on fetch errors.
    """
    logging.info(f"Fetching from {url}")
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        content = response.text.strip()

        # Heuristic check for Base64 content: starts with base64 chars, reasonable length,
        # doesn't contain common plain text indicators early on, ends with potential padding.
        # This is NOT foolproof but helps detect common base64 subscription formats.
        # More reliable check might involve trying to decode and seeing if the result looks like a list of URLs.
        is_likely_base64 = (
            len(content) > 50 and # Must be long enough
            all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r" for c in content) and
            content.count('\n') < len(content) / 10 and # Not too many newlines compared to content length (heuristic)
            (content.endswith('=') or content.endswith('==') or content[-50:].count('=') < 5) # Check for padding or lack thereof in the end
        )


        if is_likely_base64:
             decoded_content = decode_base64(content)
             if decoded_content and ("vmess://" in decoded_content or "vless://" in decoded_content or "ss://" in decoded_content or "trojan://" in decoded_content):
                 # Successfully decoded and the result looks like it contains keys
                 logging.info(f"Decoded Base64 content from {url}")
                 content = decoded_content
             else:
                 # Decoding failed or result doesn't look like keys, treat as plain text
                 logging.warning(f"Content from {url} looks like Base64 but failed to decode or result is not keys. Treating as plain text.")


        # Split into lines, filter out empty lines
        keys = [line.strip() for line in content.splitlines() if line.strip()]
        return keys

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch or error during request from {url}: {e}")
        return [] # Return empty list on fetch errors
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing {url}: {e}")
        return [] # Return empty list on other errors


def parse_key_to_v2ray_config_object(key_url):
    """
    Parses a key URL (vmess, vless, ss, trojan) into a Python dict suitable for V2Ray config.
    Returns the object if successful, None if parsing fails or format is unsupported/invalid.
    Strictly skips on errors by returning None and logging the error.
    """
    if not isinstance(key_url, str) or not key_url:
        logging.warning(f"Skipping invalid key (not a string or empty): {key_url}")
        return None

    try:
        # Attempt Base64 decode of the *part* after the protocol if it's vmess or ss base64 format
        if key_url.startswith("vmess://"):
            encoded_json = key_url[8:]
            decoded_json_str = decode_base64(encoded_json)
            if not decoded_json_str:
                 raise ValueError("Failed to base64 decode VMess data part")

            vmess_data = json.loads(decoded_json_str)

            # Basic validation for required fields (address, port, uuid)
            required = ["add", "port", "id"]
            if not all(field in vmess_data for field in required):
                 raise ValueError(f"Missing required VMess fields: {', '.join(required)}")

            # Construct V2Ray outbound settings part (simplified for testing)
            outbound_settings = {
                "vnext": [
                    {
                        "address": vmess_data.get("add", ""),
                        "port": int(vmess_data.get("port", 0)),
                        "users": [
                            {
                                "id": vmess_data.get("id", ""),
                                "alterId": int(vmess_data.get("aid", 0)),
                                "security": vmess_data.get("scy", "auto") # 'scy' is often the cipher
                            }
                        ]
                    }
                ]
            }
            stream_settings = {
                 "network": vmess_data.get("net", "tcp"),
                 "security": vess_data.get("tls", ""), # "tls" or ""
            }
            # Add specific settings based on network and security
            if stream_settings["network"] == "ws":
                 ws_settings = {"path": vmess_data.get("path", "/")}
                 headers = vmess_data.get("headers", {})
                 if headers:
                     # Convert simple headers dict to V2Ray's expected list format if necessary
                     # V2Ray expects [{"key": "...", "value": "..."}, ...]
                     # Or Clash might expect a simple dict depending on version/renderer
                     # For V2Ray config, it's typically a dict or list depending on setting
                     # Assuming headers are already in a suitable dict format from parsing
                     ws_settings["headers"] = headers # V2Ray usually accepts dict here
                 stream_settings["wsSettings"] = ws_settings

            if stream_settings["security"] == "tls":
                 tls_settings = {
                     "serverName": vmess_data.get("sni", vmess_data.get("add")), # Use sni if available, fallback to add
                     "allowInsecure": vmess_data.get("allowInsecure", "0") == "1" # Check allowInsecure param (less common in vmess json, more in vless/trojan uri)
                 }
                 # Add other TLS settings if present (alpn, fingerprint etc.)
                 stream_settings["tlsSettings"] = tls_settings
            # Add other security settings like reality if needed


            # Return a structure including the key and its V2Ray config part
            return {
                 "original_key": key_url,
                 "protocol": "vmess",
                 "settings": outbound_settings,
                 "streamSettings": stream_settings,
                 "name": vmess_data.get("ps", f"{vmess_data.get('add','?')}:{vmess_data.get('port','?')}") # Use ps as name, fallback to address:port
            }

        elif key_url.startswith("vless://"):
            # Parse VLess URI: vless://<uuid>@<host>:<port>?params#name
            parsed = urlparse(key_url)
            uuid = parsed.username
            server = parsed.hostname
            port = parsed.port
            params_str = parsed.query
            name = unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}"

            if not all([uuid, server, port]):
                 raise ValueError("Missing required VLess components (uuid, host, port)")

            # Parse query parameters
            params = {}
            if params_str:
                 for param in params_str.split('&'):
                     if '=' in param:
                         k, v = param.split('=', 1)
                         params[k] = unquote(v) # URL decode parameter values

            outbound_settings = {
                "vnext": [
                    {
                        "address": server,
                        "port": port,
                        "users": [
                            {
                                "id": uuid,
                                "encryption": params.get("encryption", "none"),
                                "flow": params.get("flow", "")
                            }
                        ]
                    }
                ]
            }
            stream_settings = {
                 "network": params.get("type", "tcp"), # 'type' in params is network
                 "security": params.get("security", ""), # 'security' in params
            }
            # Add specific settings based on network and security
            if stream_settings["network"] == "ws":
                 ws_settings = {"path": params.get("path", "/")}
                 headers_str = params.get("headers", "") # Headers param might be a JSON string value
                 if headers_str:
                     try:
                         ws_settings["headers"] = json.loads(headers_str) # Assume headers param is JSON
                     except json.JSONDecodeError:
                         logging.warning(f"Could not parse VLess headers JSON for {name[:50]}...")
                         # Optionally try to parse simple key:value string format if needed
                 stream_settings["wsSettings"] = ws_settings

            if stream_settings["security"] == "tls":
                 tls_settings = {
                     "serverName": params.get("sni", server),
                     "allowInsecure": params.get("allowInsecure", "0") == "1",
                 }
                 # Add other TLS settings if present (alpn, fingerprint etc. from params)
                 stream_settings["tlsSettings"] = tls_settings
            elif stream_settings["security"] == "reality":
                 # REALITY parsing requires extracting dest, sni, publicKey, shortId, spiderX from params
                 reality_settings = {
                     "dest": params.get("dest"),
                     "sni": params.get("sni", server),
                     "publicKey": params.get("pbk"), # pbk for publicKey
                     "shortId": params.get("sid"), # sid for shortId
                     "spiderX": params.get("spx", "/") # spx for spiderX
                 }
                 # Validate required reality fields are present
                 if not all([reality_settings.get("dest"), reality_settings.get("publicKey"), reality_settings.get("shortId")]):
                     raise ValueError("Missing required REALITY parameters (dest, pbk, sid)")
                 stream_settings["realitySettings"] = reality_settings
            # Add other security settings like xtls if needed

            return {
                 "original_key": key_url,
                 "protocol": "vless",
                 "settings": outbound_settings,
                 "streamSettings": stream_settings,
                 "name": name
            }

        elif key_url.startswith("ss://"):
             # Parse Shadowsocks URI: ss://method:password@host:port#name OR ss://base64encoded
             # Handle base64 encoded part first
             uri_part = key_url[5:]
             if '@' not in uri_part and len(uri_part) > 5: # Heuristic check if it might be base64
                 decoded_part = decode_base64(uri_part)
                 if decoded_part and '@' in decoded_part:
                     uri_part = decoded_part
                 else:
                     # Failed to decode or result doesn't have '@', treat the original uri_part as is
                     logging.warning(f"SS key looks like base64 but failed to decode or result is not SS format: {key_url[:50]}...")


             parts = uri_part.split('@')
             if len(parts) != 2:
                 raise ValueError("Invalid SS format (missing @ separator)")

             method_password = parts[0].split(':', 1)
             if len(method_password) != 2:
                 # SS method:password part can be base64 encoded too before the @.
                 # Example: ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@host:port
                 # Let's try decoding the method_password part if it doesn't contain ':'
                 if ':' not in method_password[0]:
                     decoded_method_password_part = decode_base64(method_password[0])
                     if decoded_method_password_part and ':' in decoded_method_password_part:
                         method_password = decoded_method_password_part.split(':', 1)
                         logging.info(f"Decoded SS method:password part for {key_url[:50]}...")
                     else:
                         raise ValueError("Invalid SS method:password format")
                 else:
                      raise ValueError("Invalid SS method:password format")


             method = method_password[0]
             password = method_password[1]

             server_port_name = parts[1].split('#', 1)
             server_port = server_port_name[0].split(':', 1)
             if len(server_port) != 2:
                 raise ValueError("Invalid SS format (missing server or port)")
             server = server_port[0]
             try:
                 port = int(server_port[1])
             except ValueError:
                 raise ValueError("Invalid SS port format")
             name = unquote(server_port_name[1]) if len(server_port_name) == 2 else f"ss-{server}:{port}"


             outbound_settings = {
                "servers": [
                    {
                        "address": server,
                        "port": port,
                        "method": method,
                        "password": password
                    }
                ]
             }
             # SS usually doesn't have complex stream settings in the URI format,
             # but plugins might be specified in parameters which are not covered here.
             # For basic SS, streamSettings is empty.

             return {
                 "original_key": key_url,
                 "protocol": "ss",
                 "settings": outbound_settings,
                 "streamSettings": {},
                 "name": name
             }

        elif key_url.startswith("trojan://"):
             # Parse Trojan URI: trojan://<password>@<host>:<port>?params#name
            parsed = urlparse(key_url)
            password = parsed.username # Trojan uses password as username
            server = parsed.hostname
            port = parsed.port
            params_str = parsed.query
            name = unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}"

            if not all([password, server, port]):
                 raise ValueError("Missing required Trojan components (password, host, port)")

            # Parse query parameters (for flow, sni etc.)
            params = {}
            if params_str:
                 for param in params_str.split('&'):
                     if '=' in param:
                         k, v = param.split('=', 1)
                         params[k] = unquote(v) # URL decode parameter values

            outbound_settings = {
                "servers": [
                    {
                        "address": server,
                        "port": port,
                        "password": password,
                        "flow": params.get("flow", "") # flow param (xray only)
                    }
                ]
            }
            stream_settings = {
                 "network": params.get("type", "tcp"), # 'type' in params is network (less common for trojan)
                 "security": params.get("security", "tls"), # 'security' in params, default to tls for trojan
            }

             # Trojan typically uses TLS
            if stream_settings["security"] == "tls" or stream_settings["security"] == "xtls" or stream_settings["security"] == "reality":
                 tls_settings = {
                     "serverName": params.get("sni", server),
                     "allowInsecure": params.get("allowInsecure", "0") == "1",
                 }
                 # Add other TLS/XTLS/REALITY specific settings from params (alpn, fingerprint, pbk, sid, dest, spx etc.)
                 # This part needs detailed parsing of params for XTLS/REALITY features
                 # For simplicity in this example, only basic TLS params are considered
                 stream_settings["tlsSettings"] = tls_settings # Use tlsSettings for all TLS-based security types initially

                 if stream_settings["security"] == "reality":
                     reality_settings = {
                         "dest": params.get("dest"),
                         "sni": params.get("sni", server),
                         "publicKey": params.get("pbk"),
                         "shortId": params.get("sid"),
                         "spiderX": params.get("spx", "/")
                     }
                     if not all([reality_settings.get("dest"), reality_settings.get("publicKey"), reality_settings.get("shortId")]):
                         raise ValueError("Missing required REALITY parameters (dest, pbk, sid) for Trojan+Reality")
                     stream_settings["realitySettings"] = reality_settings


            return {
                 "original_key": key_url,
                 "protocol": "trojan",
                 "settings": outbound_settings,
                 "streamSettings": stream_settings,
                 "name": name
            }


        else:
            # Automatically skip unsupported protocols
            # logging.warning(f"Skipping unsupported protocol for key: {key_url[:50]}...") # Avoid logging too much if many unsupported
            return None # Return None for unsupported protocols

    except (ValueError, KeyError, json.JSONDecodeError, base64.binascii.Error) as e:
        # Catch specific parsing errors and skip
        logging.warning(f"Skipping key due to parsing error: {key_url[:100]}... Reason: {e}")
        return None
    except Exception as e:
        # Catch any other unexpected errors during parsing and skip
        logging.error(f"Skipping key due to unexpected parsing error: {key_url[:100]}... Reason: {e}")
        return None

def generate_v2ray_config_file(v2ray_key_config_obj, filename_prefix="temp_config"):
    """Generates a full V2Ray config file from a parsed key object."""
    # Load the base template config
    try:
        with open(V2RAY_TEMPLATE_CONFIG, 'r') as f:
            v2ray_config = json.load(f)

        # Create the test outbound object
        test_outbound = {
             "protocol": v2ray_key_config_obj["protocol"],
             "settings": v2ray_key_config_obj["settings"],
             "streamSettings": v2ray_key_config_obj.get("streamSettings", {}),
             "tag": "test_proxy_out" # Assign a fixed tag for routing
        }

        # Find the outbound list and insert the test outbound at the beginning
        if 'outbounds' not in v2ray_config or not isinstance(v2ray_config['outbounds'], list):
             logging.error(f"Template config '{V2RAY_TEMPLATE_CONFIG}' is missing or has invalid 'outbounds' list.")
             return None

        # Check if an outbound with the test tag already exists (shouldn't in a clean template)
        if any(o.get('tag') == test_outbound['tag'] for o in v2ray_config['outbounds']):
             logging.warning(f"Template config already contains an outbound with tag '{test_outbound['tag']}'. Overwriting first element.")
             v2ray_config['outbounds'][0] = test_outbound
        else:
            v2ray_config['outbounds'].insert(0, test_outbound) # Insert at the beginning

        # Ensure routing rule exists for "test_proxy_in" -> "test_proxy_out"
        # This is critical. The template MUST have an inbound tagged "test_proxy_in"
        # and a rule routing traffic from "test_proxy_in" to "test_proxy_out".
        # We can add a check here, but fixing the template is better.
        # For robustness, ensure 'routing' and 'rules' exist
        if 'routing' not in v2ray_config or not isinstance(v2ray_config['routing'], dict):
             v2ray_config['routing'] = {}
        if 'rules' not in v2ray_config['routing'] or not isinstance(v2ray_config['routing']['rules'], list):
             v2ray_config['routing']['rules'] = []

        # Check if the specific routing rule exists. Add it if not.
        # This makes the script more resilient if the template is slightly off.
        required_rule_present = any(
            rule.get('type') == 'field' and
            'inboundTag' in rule and isinstance(rule['inboundTag'], list) and 'proxyin' in rule['inboundTag'] and
            rule.get('outboundTag') == 'test_proxy_out'
            for rule in v2ray_config['routing']['rules']
        )

        if not required_rule_present:
             logging.warning(f"Required routing rule 'proxyin' -> 'test_proxy_out' not found in template. Adding it.")
             # Add the rule at the beginning of the rules list
             v2ray_config['routing']['rules'].insert(0, {
                "type": "field",
                "inboundTag": ["proxyin"], # Assumes template inbound uses tag "proxyin"
                "outboundTag": "test_proxy_out"
             })

         # Also check if the required inbound exists (port and protocol matching script config)
        required_inbound_present = any(
            inbound.get('port') == PROXY_LISTEN_PORT and
            inbound.get('protocol') == PROXY_PROTOCOL and
            'tag' in inbound and 'proxyin' in inbound['tag']  # Check if 'proxyin' is in the tag or tags list
            for inbound in v2ray_config.get('inbounds', []) if isinstance(inbound, dict)
        )
         # Note: Checking if 'proxyin' is in the tag list or a single tag string
         # needs more complex logic if inbound['tag'] can be a list. Let's assume tag is a string for simplicity here
         # A better check might be: if inbound.get('tag') == 'proxyin'

         if not required_inbound_present:
             logging.error(f"Template config MUST have an inbound with protocol '{PROXY_PROTOCOL}', port {PROXY_LISTEN_PORT}, and tag 'proxyin'. Test will likely fail.")
             # We can't auto-add a complex inbound easily, so just log error.

        # Generate a unique filename for each temporary config
        # Use hash of the original key for uniqueness
        key_hash = abs(hash(v2ray_key_config_obj['original_key'])) % (10**10) # Use positive hash part
        config_path = os.path.join(OUTPUT_DIR, f"{filename_prefix}_{key_hash}.json")


        with open(config_path, 'w') as f:
            json.dump(v2ray_config, f, indent=2)

        return config_path

    except FileNotFoundError:
        logging.error(f"Error: V2Ray template config file '{V2RAY_TEMPLATE_CONFIG}' not found. Please ensure it exists.")
        return None
    except json.JSONDecodeError:
        logging.error(f"Error: V2Ray template config file '{V2RAY_TEMPLATE_CONFIG}' has invalid JSON format.")
        return None
    except Exception as e:
        logging.error(f"Error generating V2Ray config file for key: {e}")
        return None

def is_v2ray_binary_executable(binary_path):
    """Checks if the V2Ray binary exists and is executable."""
    if not isinstance(binary_path, str) or not binary_path:
        return False
    # Check if the binary is in the PATH or is a direct path
    if "/" not in binary_path and "\\" not in binary_path: # Likely just the binary name
         from shutil import which
         if which(binary_path):
              return True
         else:
              return False

    # Check a specific path
    if not os.path.exists(binary_path):
        return False
    if not os.path.isfile(binary_path):
        return False
    if not os.access(binary_path, os.X_OK): # Check executable permission on Unix-like systems
         # On Windows, os.access(..., os.X_OK) might behave differently, but checking existence is usually enough
         if sys.platform.startswith('win'):
              return True # Assume executable on Windows if file exists
         return False

    return True


def test_key_with_v2ray(v2ray_key_config_obj, test_url=PROXY_TEST_URL, timeout=TEST_TIMEOUT_PER_KEY):
    """
    Tests a V2Ray key by running the V2Ray/Xray binary and attempting an HTTP request through it.
    Returns True if successful, False otherwise.
    Handles V2Ray process lifecycle, timeouts, and logs V2Ray output on failure.
    """
    proxy_name = v2ray_key_config_obj.get("name", v2ray_key_config_obj['original_key'][:30] + '...')
    logging.info(f"Testing {v2ray_key_config_obj['protocol'].upper()}: {proxy_name}")

    # Ensure the binary exists and is executable BEFORE starting the test process
    if not is_v2ray_binary_executable(V2RAY_BINARY):
         logging.error(f"V2Ray/Xray binary '{V2RAY_BINARY}' not found or not executable. Cannot run test.")
         # This is a critical error, should be handled before thread pool if possible
         return False

    # Generate a temporary V2Ray config file for this key
    temp_config_file = generate_v2ray_config_file(v2ray_key_config_obj)
    if not temp_config_file:
        logging.warning(f"Skipping test for {proxy_name} due to config generation failure.")
        return False

    v2ray_process = None
    is_working = False # Assume not working until proven otherwise
    v2ray_stdout, v2ray_stderr = None, None # To capture binary output on error

    # --- Start V2Ray/Xray Process ---
    try:
        cmd = [V2RAY_BINARY, "run", "-config", temp_config_file]

        # Use a separate process group to ensure all child processes are killed
        preexec_fn = None
        if sys.platform == "linux" or sys.platform == "darwin": # For Unix-like systems
             preexec_fn = os.setsid # Start in a new session

        # Start the process, capture stdout/stderr but don't block yet
        v2ray_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=preexec_fn # Create a new process group on Unix
        )

        # Give V2Ray a moment to start up and open the local proxy port
        # The exact time needed can vary, 1-3 seconds is usually sufficient
        time.sleep(2) # Increased startup delay

        # Check if V2Ray process started and is still running
        if v2ray_process.poll() is not None:
             # Process has already terminated, likely due to a config error
             stdout_bytes, stderr_bytes = v2ray_process.communicate(timeout=1) # Collect output quickly
             logging.error(f"V2Ray/Xray process for {proxy_name} terminated prematurely. Exit Code: {v2ray_process.returncode}")
             if stdout_bytes: logging.error("V2Ray stdout:\n" + stdout_bytes.decode('utf-8', errors='ignore'))
             if stderr_bytes: logging.error("V2Ray stderr:\n" + stderr_bytes.decode('utf-8', errors='ignore'))
             return False # Testing failed because V2Ray didn't start

        # --- Test Connectivity via Local Proxy ---
        local_proxy_url = f"{PROXY_PROTOCOL}://127.0.0.1:{PROXY_LISTEN_PORT}"
        proxies = {
            "http": local_proxy_url,
            "https": local_proxy_url,
        }

        # Attempt to make the HTTP request through the local proxy
        # Allow a slightly shorter timeout for the request itself, leaving time for V2Ray startup/shutdown
        request_timeout = timeout - 3 # e.g., 15s total, 12s for request

        try:
            logging.debug(f"Attempting to fetch {test_url} via {local_proxy_url} for {proxy_name}...")
            response = requests.get(test_url, proxies=proxies, timeout=request_timeout)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

            # Check response status code (200 for success, 204 for generate_204)
            if response.status_code in [200, 204]:
                latency_ms = response.elapsed.total_seconds() * 1000 # Latency from requests library
                logging.info(f"Proxy {proxy_name} is working! Latency: {latency_ms:.2f}ms")
                is_working = True
            else:
                logging.warning(f"Proxy {proxy_name} failed HTTP test. Status code: {response.status_code}")
                is_working = False # HTTP status indicates failure

        except requests.exceptions.Timeout:
            logging.warning(f"Proxy {proxy_name} timed out after {request_timeout}s during HTTP test.")
            is_working = False
        except requests.exceptions.RequestException as e:
             logging.warning(f"Proxy {proxy_name} failed HTTP request via V2Ray: {e}")
             is_working = False
        except Exception as e:
            logging.error(f"An unexpected error occurred during HTTP request test for {proxy_name}: {e}")
            is_working = False


    except FileNotFoundError:
        logging.error(f"V2Ray/Xray binary '{V2RAY_BINARY}' not found. Please ensure it's downloaded and in the correct location or PATH.")
        # This should ideally be caught before the pool, but included here for robustness
        is_working = False
    except Exception as e:
        # Catch any other unexpected errors during the overall test process start/run
        logging.error(f"An unexpected error occurred during test process for {proxy_name}: {e}")
        is_working = False

    finally:
        # --- Clean up V2Ray/Xray Process ---
        if v2ray_process:
            try:
                # Try graceful termination first (SIGTERM)
                if preexec_fn: # If using process group
                    os.killpg(os.getpgid(v2ray_process.pid), subprocess.signal.SIGTERM)
                else:
                    v2ray_process.terminate()

                # Wait for a short period for graceful exit
                v2ray_process.wait(timeout=3) # Wait max 3 seconds

            except subprocess.TimeoutExpired:
                # If it didn't exit gracefully, force kill (SIGKILL)
                logging.warning(f"V2Ray/Xray process for {proxy_name} did not terminate gracefully. Killing...")
                try:
                    if preexec_fn:
                        os.killpg(os.getpgid(v2ray_process.pid), subprocess.signal.SIGKILL)
                    else:
                        v2ray_process.kill()
                except ProcessLookupError:
                    # Process already finished (race condition)
                    pass
                except Exception as e:
                     logging.error(f"Error force-terminating V2Ray/Xray process for {proxy_name}: {e}")

            except ProcessLookupError:
                 # Process already finished or wasn't found
                 pass
            except Exception as e:
                logging.error(f"Error during V2Ray/Xray process termination for {proxy_name}: {e}")

            # Capture any remaining output after termination
            try:
                 stdout_bytes, stderr_bytes = v2ray_process.communicate(timeout=1) # Use a very short timeout here
                 if stdout_bytes: logging.debug(f"V2Ray stdout ({proxy_name}):\n" + stdout_bytes.decode('utf-8', errors='ignore'))
                 if stderr_bytes: logging.debug(f"V2Ray stderr ({proxy_name}):\n" + stderr_bytes.decode('utf-8', errors='ignore'))
            except subprocess.TimeoutExpired:
                 logging.warning(f"Could not capture all V2Ray output for {proxy_name} after termination.")
            except Exception as e:
                 logging.error(f"Error capturing final V2Ray output for {proxy_name}: {e}")


        # --- Clean up temporary config file ---
        if temp_config_file and os.path.exists(temp_config_file):
            try:
                os.remove(temp_config_file)
            except Exception as e:
                logging.error(f"Error removing temp config file {temp_config_file}: {e}")

    return is_working


def convert_v2ray_to_clash(v2ray_config_obj):
    """
    Converts a parsed V2Ray key config object into a Clash proxy dictionary.
    Returns None if conversion is not supported or fails.
    """
    protocol = v2ray_config_obj.get("protocol")
    name = v2ray_config_obj.get("name", "Unnamed Proxy")
    settings = v2ray_config_obj.get("settings", {})
    stream_settings = v2ray_config_obj.get("streamSettings", {})

    try:
        if protocol == "vmess":
            vnext_users = settings.get("vnext", [])
            if not vnext_users or 'users' not in vnext_users[0] or not vnext_users[0]['users']:
                 raise ValueError("Invalid VMess settings structure")

            server = vnext_users[0].get("address")
            port = vnext_users[0].get("port")
            user = vnext_users[0]['users'][0]
            uuid = user.get("id")
            alterId = user.get("alterId", 0)
            cipher = user.get("security", "auto") # 'cipher' in Clash, 'security' in V2Ray user

            if not all([server, port, uuid]):
                raise ValueError("Missing required VMess fields for Clash conversion")

            clash_proxy = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": uuid,
                "alterId": alterId,
                "cipher": cipher,
            }

            # Stream settings
            network = stream_settings.get("network")
            security = stream_settings.get("security") # 'tls' or ''
            if network == "ws":
                 clash_proxy["network"] = "ws"
                 ws_settings = stream_settings.get("wsSettings", {})
                 clash_proxy["ws-path"] = ws_settings.get("path", "/")
                 # Clash headers format can vary, often a simple dict
                 clash_proxy["ws-headers"] = ws_settings.get("headers", {}) # Pass headers as a dict

            if security == "tls":
                 clash_proxy["tls"] = True
                 tls_settings = stream_settings.get("tlsSettings", {})
                 clash_proxy["servername"] = tls_settings.get("serverName", server) # 'servername' in Clash
                 # Clash might support skip-cert-verify instead of allowInsecure
                 clash_proxy["skip-cert-verify"] = tls_settings.get("allowInsecure", False) # Map allowInsecure to skip-cert-verify
                 # Add other TLS fields if supported by Clash and present (alpn, fingerprint)

            # Other Clash specific VMess fields like udp,grpc etc. would need checking

            return clash_proxy

        elif protocol == "vless":
            vnext_users = settings.get("vnext", [])
            if not vnext_users or 'users' not in vnext_users[0] or not vnext_users[0]['users']:
                 raise ValueError("Invalid VLess settings structure")

            server = vnext_users[0].get("address")
            port = vnext_users[0].get("port")
            user = vnext_users[0]['users'][0]
            uuid = user.get("id")
            encryption = user.get("encryption", "none") # Should be 'none' for VLess
            flow = user.get("flow", "") # VLESS flow (e.g., xtls-rprx-vision)

            if not all([server, port, uuid]):
                raise ValueError("Missing required VLess fields for Clash conversion")

            clash_proxy = {
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "encryption": encryption,
            }

            # Stream settings
            network = stream_settings.get("network")
            security = stream_settings.get("security") # 'tls', 'xtls', 'reality'

            if network == "ws":
                 clash_proxy["network"] = "ws"
                 ws_settings = stream_settings.get("wsSettings", {})
                 clash_proxy["ws-path"] = ws_settings.get("path", "/")
                 clash_proxy["ws-headers"] = ws_settings.get("headers", {})

            if security in ["tls", "xtls", "reality"]:
                 clash_proxy["tls"] = True
                 tls_settings = stream_settings.get("tlsSettings", {})
                 clash_proxy["servername"] = tls_settings.get("serverName", server)
                 clash_proxy["skip-cert-verify"] = tls_settings.get("allowInsecure", False)

                 if security == "xtls":
                     clash_proxy["flow"] = flow # XTLS flow
                     # Note: Clash might need specific parameters for XTLS beyond flow

                 elif security == "reality":
                     clash_proxy["reality-opts"] = { # Clash uses reality-opts
                         "public-key": stream_settings.get("realitySettings", {}).get("publicKey"), # 'public-key' in Clash
                         "short-id": stream_settings.get("realitySettings", {}).get("shortId"), # 'short-id' in Clash
                         "fallback": stream_settings.get("realitySettings", {}).get("dest"), # 'fallback' in Clash (dest)
                         "spiderX": stream_settings.get("realitySettings", {}).get("spiderX", "/"), # 'spiderX' in Clash
                     }
                     # Validate required reality params for Clash
                     if not all([clash_proxy["reality-opts"].get("public-key"), clash_proxy["reality-opts"].get("short-id")]):
                          raise ValueError("Missing required REALITY parameters for Clash conversion (pbk, sid)")

            # Other Clash specific VLess fields

            return clash_proxy

        elif protocol == "ss":
             servers = settings.get("servers", [])
             if not servers:
                  raise ValueError("Invalid SS settings structure")

             server_info = servers[0]
             server = server_info.get("address")
             port = server_info.get("port")
             method = server_info.get("method")
             password = server_info.get("password")

             if not all([server, port, method, password]):
                  raise ValueError("Missing required SS fields for Clash conversion")

             clash_proxy = {
                 "name": name,
                 "type": "ss",
                 "server": server,
                 "port": port,
                 "cipher": method, # 'cipher' in Clash, 'method' in V2Ray
                 "password": password,
             }
             # SS stream settings like plugin would need special handling

             return clash_proxy

        elif protocol == "trojan":
            servers = settings.get("servers", [])
            if not servers:
                 raise ValueError("Invalid Trojan settings structure")

            server_info = servers[0]
            server = server_info.get("address")
            port = server_info.get("port")
            password = server_info.get("password")
            flow = server_info.get("flow", "") # Trojan flow (xray only)

            if not all([server, port, password]):
                 raise ValueError("Missing required Trojan fields for Clash conversion")

            clash_proxy = {
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": password,
            }

            # Stream settings (usually TLS)
            security = stream_settings.get("security") # 'tls', 'xtls', 'reality'

            if security in ["tls", "xtls", "reality"]:
                clash_proxy["tls"] = True
                tls_settings = stream_settings.get("tlsSettings", {})
                clash_proxy["servername"] = tls_settings.get("serverName", server)
                clash_proxy["skip-cert-verify"] = tls_settings.get("allowInsecure", False)

                if security == "xtls":
                    clash_proxy["flow"] = flow # XTLS flow

                elif security == "reality":
                     clash_proxy["reality-opts"] = { # Clash uses reality-opts
                         "public-key": stream_settings.get("realitySettings", {}).get("publicKey"),
                         "short-id": stream_settings.get("realitySettings", {}).get("shortId"),
                         "fallback": stream_settings.get("realitySettings", {}).get("dest"),
                         "spiderX": stream_settings.get("realitySettings", {}).get("spiderX", "/"),
                     }
                     # Validate required reality params for Clash
                     if not all([clash_proxy["reality-opts"].get("public-key"), clash_proxy["reality-opts"].get("short-id")]):
                          raise ValueError("Missing required REALITY parameters for Clash conversion (pbk, sid)")

            # Other Clash specific Trojan fields

            return clash_proxy


        else:
            # Protocol not supported for Clash conversion
            logging.warning(f"Skipping Clash conversion for unsupported protocol: {protocol}")
            return None

    except (ValueError, KeyError, TypeError) as e:
        logging.warning(f"Skipping Clash conversion for key '{name}' due to data error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during Clash conversion for key '{name}': {e}")
        return None


def generate_clash_config(working_proxy_configs):
    """
    Generate a Clash configuration file from working proxy configurations.
    Includes conversion to Clash format, proxy groups, and basic rules.
    """
    clash_proxies = []
    clash_proxy_names = []

    for v2ray_config_obj in working_proxy_configs:
        clash_proxy = convert_v2ray_to_clash(v2ray_config_obj)
        if clash_proxy:
            clash_proxies.append(clash_proxy)
            clash_proxy_names.append(clash_proxy["name"]) # Collect names for groups

    # Define basic proxy groups
    proxy_groups = [
        {
            "name": "🚀 Proxy Selection", # Node Selection Group
            "type": "select",
            "proxies": clash_proxy_names if clash_proxy_names else ["DIRECT", "REJECT"] # Add all working proxy names
        },
        {
             "name": "🌐 Global", # Global Group
             "type": "select",
             "proxies": ["🚀 Proxy Selection", "DIRECT", "REJECT"] # Route through selection group or directly
        },
         {
             "name": "📈 Speedtest", # Optional Speedtest Group
             "type": "url-test", # Or 'fallback'
             "url": PROXY_TEST_URL, # URL for testing speed/availability
             "interval": 300, # Test interval in seconds
             "tolerance": 50, # Tolerance for url-test
             "proxies": clash_proxy_names if clash_proxy_names else ["DIRECT", "REJECT"]
         },
        {"name": "DIRECT", "type": "direct"},
        {"name": "REJECT", "type": "reject"},
    ]

    # Define basic routing rules (example)
    rules = [
        "MATCH,🌐 Global" # Default rule: send all traffic to the Global group
        # Add more specific rules above MATCH, e.g.:
        # "DOMAIN-SUFFIX,google.com,🌐 Global"
        # "GEOSITE,CN,DIRECT"
        # "GEOIP,CN,DIRECT"
        # "MATCH,DIRECT" # Fallback if no other rule matches
    ]

    # Construct the final Clash config dictionary
    clash_config = {
        "port": 7890,       # Default Clash ports
        "socks-port": 7891, # Default
        "allow-lan": False, # Usually False in server/testing environments
        "mode": "rule",     # Rule-based routing
        "log-level": "info",
        "external-controller": "127.0.0.1:9090", # For Clash API/Dashboard
        "proxies": clash_proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
        # Add DNS, geoip/geosite database paths etc. if needed
    }

    # Create output directory if it doesn't exist (already done in main, but safe here too)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Save the Clash configuration to YAML file
    try:
        with open(CLASH_CONFIG_FILE, "w", encoding='utf-8') as config_file:
            # Use Dumper to control output style, allow_unicode for names
            yaml.dump(clash_config, config_file, default_flow_style=False, allow_unicode=True, sort_keys=False)
        logging.info(f"Clash configuration saved to '{CLASH_CONFIG_FILE}'. Found {len(clash_proxies)} proxies for Clash.")
    except Exception as e:
        logging.error(f"Error generating or saving Clash configuration: {e}")

    # Save working keys list as a simple text file
    working_keys_path = os.path.join(OUTPUT_DIR, "working_subscription.txt")
    try:
        with open(working_keys_path, "w", encoding='utf-8') as f:
            for proxy_config in working_proxy_configs:
                f.write(f"{proxy_config['original_key']}\n")
        logging.info(f"Working keys list saved to '{working_keys_path}'. Found {len(working_proxy_configs)} working keys.")
    except Exception as e:
        logging.error(f"Error saving working keys list: {e}")


# --- Main Execution ---
def main():
    logging.info("Starting V2Ray Key Testing Script...")

    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_keys = []
    # Use a list to store parsed working key objects
    working_proxy_configs = []

    # --- Fetch Keys from Sources ---
    logging.info("\n--- Fetching Keys ---")
    source_urls = get_source_urls_from_env()
    if not source_urls:
        logging.error("No subscription source URLs provided or found. Exiting.")
        # Generate empty files to avoid errors in subsequent workflow steps
        generate_clash_config([]) # This function also saves working_subscription.txt
        sys.exit(1) # Exit with error code

    fetched_keys_results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fetch_futures = {executor.submit(fetch_subscription, url): url for name, url in source_urls.items() if validate_subscription_url(url)}
        for future in as_completed(fetch_futures):
            url = fetch_futures[future]
            try:
                keys = future.result()
                fetched_keys_results.extend(keys)
            except Exception as exc:
                logging.error(f"URL {url} generated an exception during fetch: {exc}")

    all_keys = list(set(fetched_keys_results)) # Remove duplicates
    logging.info(f"\nTotal unique potential keys fetched from all sources: {len(all_keys)}\n")

    if not all_keys:
        logging.warning("No keys fetched after processing all URLs. Exiting.")
        generate_clash_config([]) # Generate empty files
        sys.exit(0) # Exit successfully as no keys were found, which might be expected sometimes


    # --- Parse Keys ---
    logging.info("\n--- Parsing Keys ---")
    parsed_keys = []
    # Parsing is generally fast, can do without thread pool or with a smaller one
    for key in all_keys:
         parsed = parse_key_to_v2ray_config_object(key)
         if parsed:
              parsed_keys.append(parsed)
         # parse_key_to_v2ray_config_object logs errors for skipped keys


    logging.info(f"Successfully parsed {len(parsed_keys)} valid keys.")

    if not parsed_keys:
        logging.warning("No valid keys parsed after filtering. Exiting.")
        generate_clash_config([]) # Generate empty files
        sys.exit(0) # Exit successfully


    # --- Test Parsed Keys ---
    logging.info(f"\n--- Testing Keys ---")

    # Check if the binary is available before starting the test pool
    if not is_v2ray_binary_executable(V2RAY_BINARY):
        logging.error(f"Critical Error: V2Ray/Xray binary '{V2RAY_BINARY}' not found or not executable.")
        logging.error("Cannot proceed with testing. Please ensure the binary is correctly set up in your workflow.")
        generate_clash_config([]) # Generate empty files
        sys.exit(1) # Exit with critical error code


    logging.info(f"Starting connectivity test for {len(parsed_keys)} parsed keys using {V2RAY_BINARY}...")
    logging.info(f"Local proxy: {PROXY_PROTOCOL}://127.0.0.1:{PROXY_LISTEN_PORT}, Test URL: {PROXY_TEST_URL}, Timeout per key: {TEST_TIMEOUT_PER_KEY}s")

    test_futures = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit testing tasks
        test_futures = {executor.submit(test_key_with_v2ray, key_config, test_url=PROXY_TEST_URL, timeout=TEST_TIMEOUT_PER_KEY): key_config for key_config in parsed_keys}

        # Process results as they complete
        for future in as_completed(test_futures):
            key_config = test_futures[future]
            try:
                is_working = future.result()
                if is_working:
                    working_proxy_configs.append(key_config)
            except Exception as exc:
                # Exception during thread execution, should be rare if test_key_with_v2ray handles its own errors
                logging.error(f"Key '{key_config.get('name', key_config['original_key'][:50] + '...')}' generated an unhandled exception during test: {exc}")


    logging.info(f"\n--- Testing Complete ---")
    logging.info(f"Total working keys found: {len(working_proxy_configs)}")

    # --- Save Results ---
    logging.info("\n--- Saving Results ---")
    # This function will save the list of working keys to working_subscription.txt
    # and generate the Clash configuration file (needs full implementation of conversion)
    generate_clash_config(working_proxy_configs)

    if len(working_proxy_configs) == 0:
        logging.warning("No working keys were found.")
        # Depending on desired workflow behavior, you might want to exit with
        # a non-zero code here to indicate a partial failure, or 0 if finding
        # no working keys is an acceptable outcome.
        # Let's exit with 0 if the script ran successfully but found no keys.
        sys.exit(0)

    logging.info("\nV2Ray Key Testing Script finished successfully.")
    sys.exit(0) # Exit successfully

if __name__ == "__main__":
    main()
