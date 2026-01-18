# ==========================================================
# SECURE ADVANCED HACKER TERMINAL SIMULATION GAME (EDUCATIONAL)
# ==========================================================
# Features:
# - Secure Login System (hashed passwords)
# - Account lock after failed attempts
# - Terminal-based hacker simulation
# - Time-based levels
# - Encryption puzzle
# - Intrusion Detection System
# - Logging system
# ==========================================================

import time
import random
import hashlib
import os
import sys

# ---------------- GLOBAL CONFIG ----------------
USER_DB = "users.db"
LOG_FILE = "hack_log.txt"
MAX_ATTEMPTS = 3

score = 0
mistakes = 0

# ---------------- UTILITY FUNCTIONS ----------------
def slow_print(text, delay=0.02):
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def write_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

# ---------------- USER DATABASE ----------------
def init_user_db():
    if not os.path.exists(USER_DB):
        with open(USER_DB, "w") as f:
            # default admin user
            f.write("admin|" + hash_password("admin123") + "|0\n")

def read_users():
    users = {}
    with open(USER_DB, "r") as f:
        for line in f:
            u, p, a = line.strip().split("|")
            users[u] = {"password": p, "attempts": int(a)}
    return users

def write_users(users):
    with open(USER_DB, "w") as f:
        for u in users:
            f.write(f"{u}|{users[u]['password']}|{users[u]['attempts']}\n")

# ---------------- LOGIN SYSTEM ----------------
def login_system():
    clear_screen()
    slow_print("========== SECURE LOGIN ==========")
    users = read_users()

    username = input("Username: ")
    if username not in users:
        slow_print("User not found!")
        return False

    if users[username]["attempts"] >= MAX_ATTEMPTS:
        slow_print("Account locked due to multiple failed attempts!")
        return False

    password = input("Password: ")
    if hash_password(password) == users[username]["password"]:
        slow_print("Login successful!\n")
        users[username]["attempts"] = 0
        write_users(users)
        write_log("[LOGIN] User logged in successfully")
        return True
    else:
        users[username]["attempts"] += 1
        write_users(users)
        slow_print("Invalid password!")
        write_log("[LOGIN] Failed login attempt")
        return False

# ---------------- TIME INPUT ----------------
def timeout_input(prompt, limit):
    start = time.time()
    user_input = input(prompt)
    if time.time() - start > limit:
        return None
    return user_input

# ---------------- COMMAND PARSER ----------------
def parse_command(user_cmd, correct_cmd):
    if user_cmd == correct_cmd:
        return True
    if correct_cmd.startswith(user_cmd):
        slow_print(f"HINT → Did you mean: {correct_cmd}")
    else:
        slow_print("Unknown command")
    return False

# ---------------- LEVEL 1 ----------------
def level_network_scan():
    global score, mistakes
    slow_print("\n[LEVEL 1] Network Reconnaissance")
    slow_print("Command: scan network | Time: 10s")

    cmd = timeout_input("> ", 10)
    if cmd is None:
        slow_print("[TIMEOUT] IDS ALERT!")
        mistakes += 1
        return False

    if parse_command(cmd.lower(), "scan network"):
        slow_print("Scanning network...")
        time.sleep(1)
        slow_print("Ports open: 21, 22, 80, 443")
        score += 10
        write_log("[LEVEL 1] Network scanned")
        return True

    mistakes += 1
    return False

# ---------------- LEVEL 2 ----------------
def level_firewall():
    global score, mistakes
    firewall = random.choice(["BASIC", "ADVANCED", "AI"])

    slow_print(f"\n[LEVEL 2] Firewall Type: {firewall}")
    slow_print("Command: bypass firewall")

    cmd = timeout_input("> ", 10)
    if cmd is None:
        slow_print("[TIMEOUT] Firewall reset!")
        mistakes += 1
        return False

    if cmd.lower() == "bypass firewall":
        if firewall == "AI":
            slow_print("AI Firewall requires password override!")
            mistakes += 1
            return False
        score += 20
        write_log(f"[LEVEL 2] {firewall} firewall bypassed")
        slow_print("Firewall bypassed!")
        return True

    mistakes += 1
    return False

# ---------------- LEVEL 3 ----------------
def level_password_crack():
    global score, mistakes
    password = str(random.randint(1000, 9999))
    attempts = 3

    slow_print("\n[LEVEL 3] Password Cracking")
    slow_print("4-digit encrypted key detected")

    while attempts > 0:
        guess = input("Enter key: ")
        if guess == password:
            slow_print("Password cracked!")
            score += 30
            write_log("[LEVEL 3] Password cracked")
            return True
        else:
            attempts -= 1
            slow_print(f"Wrong key! Attempts left: {attempts}")

    slow_print("[IDS] Intrusion detected! System trace active!")
    mistakes += 2
    return False

# ---------------- LEVEL 4 ----------------
def level_encryption():
    global score, mistakes
    slow_print("\n[LEVEL 4] Caesar Cipher Decryption")

    plain = "CYBERSECURITY"
    key = random.randint(1, 5)

    encrypted = ""
    for c in plain:
        encrypted += chr(((ord(c) - 65 + key) % 26) + 65)

    slow_print(f"Encrypted Text: {encrypted}")
    slow_print("Decrypt original word:")

    ans = input("> ").upper()
    if ans == plain:
        slow_print("Decryption successful!")
        score += 40
        write_log("[LEVEL 4] Encryption cracked")
        return True

    slow_print("Decryption failed!")
    mistakes += 1
    return False
# ---------------- LEVEL 5 ----------------
def level_system_enum():
    global score, mistakes
    slow_print("\n[LEVEL 5] System Enumeration")
    slow_print("Command: enum system")

    cmd = input("> ").lower()
    if cmd == "enum system":
        slow_print("Enumerating users...")
        time.sleep(1)
        slow_print("Users found: admin, analyst, guest")
        score += 15
        write_log("[LEVEL 5] System enumerated")
        return True

    slow_print("Enumeration failed!")
    mistakes += 1
    return False
# ---------------- LEVEL 6 ----------------

def level_hash_identify():
    global score, mistakes
    slow_print("\n[LEVEL 6] Hash Identification")
    slow_print("Hash: 5e884898da28047151d0e56f8dc6292773603d0d")
    slow_print("Question: Which algorithm?")

    ans = input("> ").lower()
    if ans == "sha256":
        slow_print("Correct! SHA-256 identified.")
        score += 20
        write_log("[LEVEL 6] Hash identified")
        return True

    slow_print("Wrong hash type!")
    mistakes += 1
    return False
# ---------------- LEVEL 7 ----------------

def level_port_exploit():
    global score, mistakes
    slow_print("\n[LEVEL 7] Port Exploitation")
    slow_print("Open Ports: 21, 22, 80")
    slow_print("Which port is vulnerable?")

    port = input("> ")
    if port == "21":
        slow_print("FTP Exploit successful!")
        score += 20
        write_log("[LEVEL 7] FTP exploited")
        return True

    slow_print("Exploit failed!")
    mistakes += 1
    return False
# ---------------- LEVEL 8 ----------------

def level_cover_tracks():
    global score, mistakes
    slow_print("\n[LEVEL 8] Covering Tracks")
    slow_print("Command: clear logs")

    cmd = input("> ").lower()
    if cmd == "clear logs":
        slow_print("System logs cleared.")
        score += 15
        write_log("[LEVEL 8] Logs cleared")
        return True

    slow_print("Logs not cleared!")
    mistakes += 1
    return False
# ---------------- LEVEL 9 ----------------

def level_social_engineering():
    global score, mistakes
    slow_print("\n[LEVEL 9] Social Engineering")
    slow_print("Employee forgot password.")
    slow_print("Best action?")
    slow_print("A) Threaten  B) Help Desk Reset  C) Brute Force")

    choice = input("> ").upper()
    if choice == "B":
        slow_print("Correct decision!")
        score += 20
        write_log("[LEVEL 9] Social engineering success")
        return True

    slow_print("Suspicious activity detected!")
    mistakes += 1
    return False
# ---------------- LEVEL 10 ----------------

def level_root_access():
    global score, mistakes
    slow_print("\n[LEVEL 10] ROOT ACCESS")
    slow_print("Final Command required:")
    slow_print("grant root access")

    cmd = input("> ").lower()
    if cmd == "grant root access":
        slow_print("ROOT ACCESS GRANTED 🔓")
        score += 30
        write_log("[LEVEL 10] Root access achieved")
        return True

    slow_print("ACCESS DENIED!")
    mistakes += 2
    return False






# ---------------- RESULT ----------------
def show_result():
    slow_print("\n=========== FINAL RESULT ===========")
    slow_print(f"Score     : {score}")
    slow_print(f"Mistakes  : {mistakes}")

    if score >= 80 and mistakes <= 1:
        slow_print("RANK: PERFECT HACKER 🏆")
    elif score >= 50:
        slow_print("RANK: SYSTEM ANALYST")
    else:
        slow_print("RANK: ACCESS DENIED ❌")

    slow_print("Logs saved in hack_log.txt")

# ---------------- MAIN GAME ----------------
def start_game():
    clear_screen()
    slow_print("======================================")
    slow_print("  SECURE HACKER TERMINAL SIMULATOR ")
    slow_print("  EDUCATIONAL USE ONLY (LEGAL) ")
    slow_print("======================================\n")

    open(LOG_FILE, "w").close()

    if not login_system():
        return

    if not level_network_scan(): show_result(); return
    if not level_firewall(): show_result(); return
    if not level_password_crack(): show_result(); return
    if not level_encryption(): show_result(); return
    if not level_system_enum(): show_result(); return
    if not level_hash_identify(): show_result(); return
    if not level_port_exploit(): show_result(); return
    if not level_cover_tracks(): show_result(); return
    if not level_social_engineering(): show_result(); return
    if not level_root_access(): show_result(); return

    slow_print("\n🔥 ALL LEVELS CLEARED 🔥")
    slow_print("FULL SYSTEM COMPROMISED")
    show_result()
    # ---------------- PROGRAM START ----------------
if __name__ == "__main__":
    init_user_db()     # user database create karega
    start_game()       # game start karega

