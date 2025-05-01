import requests
import subprocess
import os
import json
import base64
import yaml
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
DEFAULT_SOURCE_URLS = {
    "key1": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",
    "key2": "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mixbase64",
    "key3": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
    "key4": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "key5": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
    "key6": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY.txt",
}
OUTPUT_DIR = "subscription"
WORKING_KEYS_FILE = "working_subscription.txt"
CLASH_CONFIG_FILE = "clash_config.yaml"
MAX_WORKERS = 15
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 10

# --- Utility Functions ---
def get_source_urls_from_env():
    """Fetch subscription URLs from environment variables or use defaults."""
    urls = os.getenv("SUBSCRIPTION_URLS")
    if urls:
        try:
            return json.loads(urls)  # Expecting a JSON-formatted string in the environment variable
        except json.JSONDecodeError as e:
            print(f"Error parsing SUBSCRIPTION_URLS from environment: {e}")
    return DEFAULT_SOURCE_URLS

def validate_subscription_url(url):
    """Validate the subscription URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Check for valid scheme and domain
    except Exception as e:
        print(f"Invalid URL format: {url}, Error: {e}")
        return False

def parse_vmess_key(url):
    """Parse a VMess key into a Clash-compatible proxy configuration."""
    try:
        # Ensure the key starts with "vmess://"
        if not url.startswith("vmess://"):
            raise ValueError("Key does not start with 'vmess://'")

        # Base64 decode the key
        decoded_data = base64.b64decode(url[8:]).decode("utf-8")

        # Parse the decoded JSON data
        vmess_data = json.loads(decoded_data)

        # Ensure required fields are present
        required_fields = ["ps", "add", "port", "id"]
        for field in required_fields:
            if field not in vmess_data:
                raise KeyError(f"Missing required field: {field}")

        # Return a Clash-compatible proxy configuration
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
    except (ValueError, KeyError, json.JSONDecodeError, base64.binascii.Error) as e:
        # Log specific error details
        print(f"Error parsing VMess key: {url}, Reason: {e}")
        return None

def test_proxy(proxy):
    """Simulate GUI-like testing for a proxy (e.g., TCP connection, latency)."""
    try:
        server = proxy["server"]
        port = proxy["port"]
        start_time = time.time()

        # Test TCP connectivity
        result = subprocess.run(
            ["nc", "-zv", server, str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TEST_TIMEOUT,
        )

        latency = (time.time() - start_time) * 1000  # Convert to milliseconds
        if result.returncode == 0:
            print(f"Proxy {proxy['name']} is working! Latency: {latency:.2f}ms")
            return True, latency
        else:
            print(f"Proxy {proxy['name']} failed connectivity test.")
            return False, None
    except Exception as e:
        print(f"Error testing proxy {proxy['name']}: {e}")
        return False, None

def generate_clash_config(proxies):
    """Generate a Clash configuration file."""
    clash_config = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "auto",
                "type": "select",
                "proxies": [proxy["name"] for proxy in proxies] if proxies else ["DIRECT"],  # Fallback to DIRECT
            }
        ],
        "rules": ["MATCH,auto"],
    }

    with open(CLASH_CONFIG_FILE, "w") as config_file:
        yaml.dump(clash_config, config_file, default_flow_style=False)

    if not proxies:
        print("Warning: No proxies were added to the Clash configuration.")
    return len(proxies)

# --- Main Execution ---
def main():
    print("Starting V2Ray Key Testing Script...")
    all_keys = []
    working_proxies = []

    # Fetch subscription URLs
    source_urls = get_source_urls_from_env()
    print(f"Using source URLs: {source_urls}")

    # Fetch and parse keys
    for protocol, url in source_urls.items():
        if not validate_subscription_url(url):
            print(f"Skipping invalid URL: {url}")
            continue

        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            keys = [line.strip() for line in response.text.splitlines() if line.strip()]
            all_keys.extend(keys)
        except Exception as e:
            print(f"Failed to fetch keys from {url}: {e}")

    print(f"Total fetched keys: {len(all_keys)}")

    # Test keys and collect working ones
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for key in all_keys:
            proxy = parse_vmess_key(key)
            if proxy:
                futures.append(executor.submit(test_proxy, proxy))
            else:
                print(f"Skipping unsupported or invalid key: {key}")

        for future in futures:
            try:
                is_working, latency = future.result()
                if is_working:
                    working_proxies.append(proxy)
            except Exception as e:
                print(f"Error in proxy testing: {e}")

    print(f"Total working proxies: {len(working_proxies)}")

    # Save working keys
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, WORKING_KEYS_FILE), "w") as working_file:
        for proxy in working_proxies:
            working_file.write(f"{proxy}\n")

    # Generate Clash configuration
    generate_clash_config(working_proxies)
    print(f"Clash configuration saved to '{CLASH_CONFIG_FILE}'.")

if __name__ == "__main__":
    main()
