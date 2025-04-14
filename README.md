# V2Ray Key Tester & Provider

[![Test Keys Workflow Status](https://github.com/victorgeel/v2ray-key-tester/actions/workflows/test_and_upload_keys.yml/badge.svg)](https://github.com/victorgeel/v2ray-key-tester/actions/workflows/test_and_upload_keys.yml)

## About This Project

This repository automatically fetches V2Ray (VMess, VLESS), Trojan, and Shadowsocks (SS) configuration links from various public sources on the internet. It then tests these configurations for availability using the [Xray-core](https://github.com/XTLS/Xray-core) binary. Working keys are collected and made available through direct subscription links hosted within this repository and via a Telegram bot.

The primary goal is to provide users with readily available, tested proxy configurations. The process is fully automated using GitHub Actions and runs periodically (typically hourly).

## Features

* **Automated Fetching:** Gathers potential keys from multiple public subscription links/lists.
* **Connectivity Testing:** Uses `Xray-core` (`run -test`) to verify if keys are operational.
* **GitHub-Hosted Subscriptions:** Provides direct subscription links containing working keys, hosted via GitHub Pages / raw file access.
* **Telegram Bot Integration:** Offers an alternative way to get working keys via Telegram.
* **Regular Updates:** Automatically runs via GitHub Actions to refresh the key lists.

## How to Use

There are two main ways to get the working keys:

### 1. Direct Subscription Links

Working keys are automatically saved into `.txt` files within the `/subscription` directory of this repository. You can use the `raw.githubusercontent.com` URLs for these files directly in compatible VPN clients (like v2rayN, v2rayNG, Clash, Shadowrocket, etc.).

**Base URL:** `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/`

**Example Subscription Links:**

* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_key1.txt`
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_key2.txt`
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_key3.txt`
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_key4.txt`
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_key5.txt`
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_key6.txt`
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_hk.txt` (Hong Kong)
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_jp.txt` (Japan)
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_sg.txt` (Singapore)
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_us.txt` (United States)
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_tw.txt` (Taiwan)
* `https://raw.githubusercontent.com/victorgeel/v2ray-key-tester/main/subscription/working_uk.txt` (United Kingdom)

*Note: Each file contains up to 1500 working keys found from the corresponding source.*

### 2. Telegram Bot

You can interact with the Telegram bot to receive working keys.

* **Bot Username:** `@geekey_bot`
* **Direct Link:** [t.me/geekey_bot](https://t.me/geekey_bot)

Send `/start` to the bot for initial instructions and `/help` to see the available commands for fetching keys. You can typically request keys by command (e.g., `/key1`, `/us`) and optionally specify the number of keys you want (e.g., `/us 20`) or request all available (`/us all`).

## How It Works (Briefly)

1.  A GitHub Actions workflow ([`.github/workflows/test_and_upload_keys.yml`](./.github/workflows/test_and_upload_keys.yml)) runs on a schedule (e.g., hourly).
2.  It checks out the repository code.
3.  It runs the Python script ([`test_v2ray_keys.py`](./test_v2ray_keys.py)).
4.  The Python script:
    * Downloads the latest Xray-core binary.
    * Fetches raw data from the URLs defined in `SOURCE_URLS`.
    * Decodes Base64 if necessary and extracts potential key URLs.
    * Tests each unique key using `xray run -test`.
    * Collects working keys, sorted and limited to 1500 per source.
    * Writes the working keys to `.txt` files inside the `subscription/` directory.
5.  The workflow commits any changes in the `subscription/` directory back to the repository.
6.  (Optional: The workflow might also sync these files to a Cloudflare R2 bucket if configured, e.g., for the Telegram bot).

## Disclaimer

* The keys provided here are gathered from **publicly available sources** on the internet.
* The **stability, speed, and security** of these keys are **not guaranteed**.
* These keys may become invalid or stop working **at any time** without notice.
* Use these keys **at your own risk**. The maintainer of this repository is not responsible for how these keys are used.

## Contributing

Suggestions for new, reliable, and publicly accessible source URLs are welcome. Please open an issue to discuss potential additions.

## License

(Optional: Add license information here if you choose to add a LICENSE file, e.g., MIT License).

