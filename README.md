# 🛑 Educational Remote Access Trojan (RAT) – Proof of Concept

> ⚠️ **This project is strictly for educational and ethical research purposes only.**  
> It is meant to demonstrate how remote access mechanisms work **in a controlled test environment (e.g., a virtual machine)**.  
> **Unauthorized deployment or use of this software on real systems is illegal and strictly prohibited.**

---

## 💡 Overview

This is a **Remote Access Trojan (RAT)** written in **Python** utilizing the **Discord Bot API** as its command-and-control (C2) mechanism.  
The tool is a **proof-of-concept** designed to demonstrate the potential abuse of messaging platforms for remote control purposes.

---

## ToDo Feature List:

### 🛠 On Startup Behavior
- **Adds itself in startup:** 
  - `regedit` under `"Run"`  
  - `shell:startup` folder
- **Auto-Stealer**  
  - Steals Discord tokens, browser cookies, Steam username, and more on first launch
- **Discord Injection**  
  - Injects JavaScript to track password changes and capture new + old tokens
- Checks for existing instances  
  - If already running, terminates the one with **lower permissions**

---

## 🔧 Commands

### 🎯 Stealers
- `!token` – Steals Discord token  
- `!roblox` – Steals Roblox cookies  
- `!browser` – Steals browser history, passwords, credit cards, and cookies  

### 📸 Surveillance
- `!screenshot` – Takes a screenshot of the desktop  
- `!webcam` – Captures a webcam photo  
- `!information` – Displays basic system information  

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
- `!no_reset` – Disables the "Reset this PC" option  

### 🧨 Destructive Actions
- `!encrypt (dir/*)` – Encrypts files with `.hzzh` extension  
- `!selfdestruct` – Deletes all files and cleans traces  

### 📂 File & Directory Control
- `!list` – Lists files in the current directory  
- `!cd` – Changes working directory  
- `!exec (path)` – Executes a file at a given path  
- `!download` – Downloads a file from the victim’s PC  
- `!upload` – Uploads a file to the victim’s PC  

### ⚙️ Process & Shell Control
- `!tasks` – Lists all running tasks  
- `!taskkill "task"` – Kills a specified task  
- `!shell "cmd"` – Executes a shell command
- `!cmd "cmd"` – Executes a CMD command

---

## ⚙️ Requirements

- Python 3.9
