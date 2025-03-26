# KTG StealthBot

KTG Stealthbot is a stealthy cryptocurrency miner that operates silently in the background, collecting valuable system information and performing tasks like clipboard monitoring, password extraction, keylogging, and more. It runs the powerful XMRig miner to mine Monero cryptocurrency. With GhostMiner, the system remains undetected while executing its functions, making it an ideal tool for stealthy operations.

## Features

| **Feature**                    | **Description**                                                                 |
|---------------------------------|---------------------------------------------------------------------------------|
| **Monero Mining**               | Runs the XMRig miner to mine Monero using the system's CPU power.               |
| **Clipboard Monitoring**        | Monitors the clipboard for cryptocurrency addresses and replaces them with predefined wallet addresses. |
| **Password Extraction**         | Extracts saved passwords from browsers like Chrome, Edge, Brave, and Opera.     |
| **System Info Collection**      | Gathers detailed system information including installed apps, running processes, and wifi passwords. |
| **Keylogging**                  | Logs keystrokes and sends the data to a remote server for further analysis.     |
| **Startup Persistence**         | Sets up a script that ensures XMRig starts automatically with Windows to keep mining even after reboot. |
| **Remote Control**              | Executes custom scripts hosted remotely via HTTP.                              |
| **Cryptocurrency Address Replacement** | Automatically replaces cryptocurrency addresses found on the clipboard with predefined addresses. |

## Requirements

- Python 3.x

```bash
pip install flask requests pyperclip pynput pycryptodome psutil pywin32
```
## How It Works
GhostMiner:
1. Mining Setup: Downloads and sets up XMRig miner from a remote URL and configures it to start on Windows startup.

2. Clipboard Monitoring: Monitors clipboard for cryptocurrency addresses and replaces them with a specified wallet address.

3. Password Extraction: Extracts passwords from browsers and stores them in a secure location.

4. Keystroke Logging: Captures and logs keystrokes on the system and sends them to a remote server.

5. System Information Collection: Collects detailed system information and sends it to a specified endpoint.

6. Remote Script Execution: Downloads and runs additional scripts or payloads.

==========================================================================================
===========================================================================================

Data Collector Server:
This Flask-based server collects and stores system data from clients. It allows you to log various system information such as browser credentials, system info, keylogs, IP data, and more.

1. Save Data: Saves browser credentials (URL, username, password) sent from clients.

2. Save Keylog: Logs keystrokes received from clients and stores them.

3. Save IP Info: Fetches and saves IP-related information from the client using ipinfo.io.

4. Save System Info: Stores detailed system information like CPU, RAM, OS, and installed apps.

5. Wifi Passwords: Saves WiFi passwords collected from the client system.

6. Clipboard Monitoring: Saves clipboard contents sent from the client.

7. Process Monitoring: Logs running processes from the client system.

## API Endpoints

### `/save_data`
**Method**: `POST`

- **Description**: Saves browser credentials (URL, username, password) sent from clients.
- **Request Body**:
    ```json
    {
      "data": [
        {
          "browser": "Chrome",
          "url": "https://example.com",
          "username": "user",
          "password": "password123",
          "user": "user1"
        }
      ]
    }
    ```
- **Response**:
    ```json
    {
      "message": "Data saved successfully",
      "client_ip": "192.168.1.1"
    }
    ```

### `/save_keylog`
**Method**: `POST`

- **Description**: Logs keystrokes received from clients and stores them.
- **Request Body**: Form data: `log=<keylog data>`
- **Response**:
    ```json
    {
      "message": "Keylog saved successfully",
      "client_ip": "192.168.1.1"
    }
    ```

### `/save_ip`
**Method**: `POST`

- **Description**: Fetches and saves IP-related information from the client.
- **Request Body**:
    ```json
    {
      "ip_info": {
        "hostname": "localhost",
        "username": "user1",
        "os": "Windows",
        "cpu": "Intel i7",
        "ram": "16GB"
      }
    }
    ```
- **Response**:
    ```json
    {
      "message": "IP info saved successfully",
      "client_ip": "192.168.1.1"
    }
    ```

### `/save_sysinfo`
**Method**: `POST`

- **Description**: Saves detailed system information such as hostname, username, OS, RAM, WiFi passwords, clipboard data, installed apps, and running processes.
- **Request Body**:
    ```json
    {
      "hostname": "localhost",
      "username": "user1",
      "os": "Windows",
      "cpu": "Intel i7",
      "ram": "16GB",
      "wifi_passwords": [
        {"SSID": "HomeWiFi", "Password": "wifi123"}
      ],
      "clipboard": "Some clipboard content",
      "installed_apps": ["Chrome", "VSCode"],
      "running_processes": [
        {"pid": 1234, "name": "chrome.exe"}
      ]
    }
    ```
- **Response**:
    ```json
    {
      "message": "System info saved successfully",
      "client_ip": "192.168.1.1"
    }
    ```

## Error Responses

- **400 Bad Request**: Invalid or missing required data.
- **500 Internal Server Error**: Server-side error during data processing.

## Security Warning

**Privacy Warning**: These scripts monitor and log sensitive information such as passwords, clipboard data, and keystrokes. They should only be used for educational purposes or authorized testing.

**Legality**: Ensure you have explicit permission to run these scripts on any system. Unauthorized use may be illegal.



