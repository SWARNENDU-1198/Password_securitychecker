"""
Password Security Checker
-------------------------
A menu-driven command-line application that analyses password strength,
generates strong passwords, demonstrates secure password hashing and
audits a list of passwords from a file.

Author : Akash
Course : B.Tech-M.Tech (Integrated) CSE - Cyber Security, NFSU Dharwad
Activity: TA-2 Python Application Development

Uses only the Python standard library (no installation needed).
Run with:  python password_checker.py
"""

import os
import sys
import json
import math
import string
import secrets
import hashlib
import getpass
from datetime import datetime

# ----------------------------------------------------------------------
# Configuration / constants
# ----------------------------------------------------------------------
HISTORY_FILE = "password_history.json"
GUESSES_PER_SECOND = 1e10          # offline attack with a modern GPU rig
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"

# A small built-in list of the most commonly used (and leaked) passwords
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
    "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
    "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew",
    "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars", "klaster",
    "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "welcome", "admin",
    "password1", "password123", "admin123", "qwerty123", "india123",
    "india", "welcome123", "login", "passw0rd", "p@ssw0rd", "abcd1234",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                          "0": "o", "$": "s", "5": "s", "7": "t"})

# ----------------------------------------------------------------------
# Terminal colours (ANSI). Disabled automatically if not supported.
# ----------------------------------------------------------------------
if os.name == "nt":
    os.system("")                  # enables ANSI colours on Windows 10+

USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"


def color(text, code):
    """Wrap text in an ANSI colour code."""
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def red(t):    return color(t, "91")
def green(t):  return color(t, "92")
def yellow(t): return color(t, "93")
def cyan(t):   return color(t, "96")
def bold(t):   return color(t, "1")


RATING_COLOURS = {
    "Very Weak": red, "Weak": red, "Moderate": yellow,
    "Strong": green, "Very Strong": green,
}

# ----------------------------------------------------------------------
# Pattern detection helpers
# ----------------------------------------------------------------------
def has_sequence(pwd, run=3):
    """True if pwd has `run` or more consecutive ascending/descending
    characters, e.g. 'abc', '123', 'cba', '987'."""
    p = pwd.lower()
    for i in range(len(p) - run + 1):
        chunk = p[i:i + run]
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
    return False


def has_keyboard_pattern(pwd, run=4):
    """True if pwd contains `run` adjacent keys from a keyboard row,
    e.g. 'qwer', 'asdf', 'zxcv' (forwards or backwards)."""
    p = pwd.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run + 1):
            pattern = row[i:i + run]
            if pattern in p or pattern[::-1] in p:
                return True
    return False


def has_repeats(pwd, run=3):
    """True if the same character repeats `run` or more times in a row."""
    count = 1
    for i in range(1, len(pwd)):
        count = count + 1 if pwd[i] == pwd[i - 1] else 1
        if count >= run:
            return True
    return False


def has_year(pwd):
    """True if pwd contains a year between 1950 and 2039."""
    for i in range(len(pwd) - 3):
        part = pwd[i:i + 4]
        if part.isdigit() and 1950 <= int(part) <= 2039:
            return True
    return False


def is_leet_common(pwd):
    """True if the password is just a common word with simple tweaks:
    leet-speak ('P@ssw0rd' -> 'password') or added digits/symbols
    ('Summer2024!' -> 'summer', 'india@123' -> 'india')."""
    plain = pwd.lower().translate(LEET_MAP)
    letters_only = "".join(c for c in pwd.lower() if c.isalpha())
    return plain in COMMON_PASSWORDS or letters_only in COMMON_PASSWORDS


# ----------------------------------------------------------------------
# Core analysis
# ----------------------------------------------------------------------
def charset_size(pwd):
    """Size of the character pool the password draws from."""
    pool = 0
    if any(c.islower() for c in pwd): pool += 26
    if any(c.isupper() for c in pwd): pool += 26
    if any(c.isdigit() for c in pwd): pool += 10
    if any(not c.isalnum() for c in pwd): pool += 32
    return pool


def calculate_entropy(pwd):
    """Entropy in bits = length x log2(pool size)."""
    pool = charset_size(pwd)
    return round(len(pwd) * math.log2(pool), 1) if pool else 0.0


def format_time(seconds):
    """Convert seconds into a human-readable duration."""
    if seconds < 1:
        return "Instantly"
    units = [("centuries", 3153600000), ("years", 31536000), ("days", 86400),
             ("hours", 3600), ("minutes", 60), ("seconds", 1)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "centuries" and value > 1e6:
                return "Millions of centuries+"
            return f"{value:,.0f} {name}"
    return "Instantly"


def analyse_password(pwd):
    """Analyse a password and return a dictionary with the result."""
    checks = {
        "At least 8 characters":         len(pwd) >= 8,
        "At least 12 characters":        len(pwd) >= 12,
        "Contains lowercase letters":    any(c.islower() for c in pwd),
        "Contains uppercase letters":    any(c.isupper() for c in pwd),
        "Contains digits":               any(c.isdigit() for c in pwd),
        "Contains special symbols":      any(not c.isalnum() for c in pwd),
        "Not a common password":         pwd.lower() not in COMMON_PASSWORDS,
        "Not a common word + tweaks":  not is_leet_common(pwd),
        "No sequences (abc, 123)":       not has_sequence(pwd),
        "No keyboard patterns (qwer)":   not has_keyboard_pattern(pwd),
        "No repeated characters (aaa)":  not has_repeats(pwd),
        "No year / date inside":         not has_year(pwd),
    }

    # ---- scoring (out of 100) ----
    score = 0
    score += 15 if len(pwd) >= 8 else len(pwd)
    score += 10 if len(pwd) >= 12 else 0
    score += 10 if len(pwd) >= 16 else 0
    score += 10 if checks["Contains lowercase letters"] else 0
    score += 10 if checks["Contains uppercase letters"] else 0
    score += 10 if checks["Contains digits"] else 0
    score += 15 if checks["Contains special symbols"] else 0
    if pwd and len(set(pwd)) / len(pwd) >= 0.6:
        score += 10                                      # good variety

    penalties = {
        "No sequences (abc, 123)": 15,
        "No keyboard patterns (qwer)": 15,
        "No repeated characters (aaa)": 10,
        "No year / date inside": 10,
        "Not a common word + tweaks": 30,
    }
    for check, points in penalties.items():
        if not checks[check]:
            score -= points
    if pwd.isdigit():
        score -= 10
    if not checks["Not a common password"]:
        score = min(score, 5)
    score = max(0, min(100, score))

    # ---- entropy & crack time ----
    # Each predictable pattern lets an attacker skip guesses, so we
    # reduce the "effective" entropy by 10 bits per pattern found.
    entropy = calculate_entropy(pwd)
    pattern_checks = ["No sequences (abc, 123)", "No keyboard patterns (qwer)",
                      "No repeated characters (aaa)", "No year / date inside"]
    entropy = round(max(0.0, entropy - 10 * sum(not checks[c] for c in pattern_checks)), 1)
    if not checks["Not a common password"]:
        crack_seconds = 0                                # first guesses tried
    elif not checks["Not a common word + tweaks"]:
        crack_seconds = 10                               # dictionary + rules attack
    else:
        crack_seconds = (2 ** entropy) / 2 / GUESSES_PER_SECOND

    if score < 30:   rating = "Very Weak"
    elif score < 50: rating = "Weak"
    elif score < 70: rating = "Moderate"
    elif score < 85: rating = "Strong"
    else:            rating = "Very Strong"

    return {
        "length": len(pwd),
        "score": score,
        "rating": rating,
        "entropy": entropy,
        "crack_time": format_time(crack_seconds),
        "checks": checks,
        "suggestions": make_suggestions(checks),
    }


def make_suggestions(checks):
    """Turn failed checks into simple advice."""
    advice = {
        "At least 12 characters": "Use at least 12 characters (longer is stronger).",
        "Contains uppercase letters": "Add uppercase letters (A-Z).",
        "Contains lowercase letters": "Add lowercase letters (a-z).",
        "Contains digits": "Add some digits (0-9).",
        "Contains special symbols": "Add special symbols such as ! @ # $ %.",
        "Not a common password": "This is a well-known password. Never use it.",
        "Not a common word + tweaks": "A common word with tweaks (P@ssw0rd, Summer2024!) is guessed in seconds.",
        "No sequences (abc, 123)": "Avoid sequences like 'abc' or '123'.",
        "No keyboard patterns (qwer)": "Avoid keyboard patterns like 'qwerty' or 'asdf'.",
        "No repeated characters (aaa)": "Avoid repeating the same character.",
        "No year / date inside": "Avoid years and birth dates.",
    }
    return [advice[c] for c, ok in checks.items() if not ok and c in advice]


def mask(pwd):
    """Show only the first and last character: 'secret' -> 's****t'."""
    if len(pwd) <= 2:
        return "*" * len(pwd)
    return pwd[0] + "*" * (len(pwd) - 2) + pwd[-1]


def score_bar(score, width=30):
    """Text progress bar for the score."""
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


# ----------------------------------------------------------------------
# Password generation
# ----------------------------------------------------------------------
WORDS = ["river", "tiger", "cloud", "mango", "pixel", "rocket", "silver",
         "forest", "planet", "candle", "thunder", "orbit", "falcon", "maple",
         "copper", "glacier", "lemon", "harbor", "nebula", "quartz", "violet",
         "canyon", "ember", "willow", "summit", "cobalt", "meadow", "zephyr"]


def generate_password(length=16):
    """Cryptographically secure random password containing at least one
    lowercase, uppercase, digit and symbol."""
    pools = [string.ascii_lowercase, string.ascii_uppercase,
             string.digits, SYMBOLS]
    while True:
        chars = [secrets.choice(p) for p in pools]
        all_chars = "".join(pools)
        chars += [secrets.choice(all_chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(chars)
        pwd = "".join(chars)
        result = analyse_password(pwd)
        if result["score"] >= 85:                        # retry rare weak picks
            return pwd


def generate_passphrase(words=4):
    """Easy-to-remember passphrase, e.g. 'Tiger-Orbit-Maple-Ember-47'."""
    chosen = [secrets.choice(WORDS).capitalize() for _ in range(words)]
    return "-".join(chosen) + "-" + str(secrets.randbelow(90) + 10)


# ----------------------------------------------------------------------
# Hashing demonstration
# ----------------------------------------------------------------------
def hash_demo(pwd):
    """Show plain SHA-256 vs salted PBKDF2-HMAC-SHA256 hashing."""
    sha = hashlib.sha256(pwd.encode()).hexdigest()
    salt1, salt2 = os.urandom(16), os.urandom(16)
    pbkdf1 = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt1, 100_000).hex()
    pbkdf2 = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt2, 100_000).hex()
    return sha, (salt1.hex(), pbkdf1), (salt2.hex(), pbkdf2)


# ----------------------------------------------------------------------
# History (stores only masked passwords - never the real ones)
# ----------------------------------------------------------------------
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_history(entry):
    history = load_history()
    history.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


# ----------------------------------------------------------------------
# User interface
# ----------------------------------------------------------------------
def read_password(prompt):
    """Read a password without showing it on screen (when possible)."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt)


def print_header():
    print(cyan("=" * 58))
    print(cyan(bold("            PASSWORD SECURITY CHECKER  v1.0")))
    print(cyan("      Analyse | Generate | Hash | Audit your passwords"))
    print(cyan("=" * 58))


def print_menu():
    print("\n" + bold("MAIN MENU"))
    print("  1. Check password strength")
    print("  2. Generate a strong password")
    print("  3. Hashing demo (why we hash and salt passwords)")
    print("  4. Audit passwords from a file")
    print("  5. View check history")
    print("  6. Exit")


def show_report(pwd, r):
    paint = RATING_COLOURS[r["rating"]]
    print("\n" + bold("-------------------- ANALYSIS REPORT --------------------"))
    print(f"  Password     : {mask(pwd)}  ({r['length']} characters)")
    print(f"  Score        : {paint(score_bar(r['score']))} {paint(str(r['score']) + '/100')}")
    print(f"  Rating       : {paint(bold(r['rating']))}")
    print(f"  Entropy      : {r['entropy']} bits")
    print(f"  Crack time   : {r['crack_time']}  (offline, 10 billion guesses/sec)")
    print("\n  " + bold("Security checks:"))
    for check, ok in r["checks"].items():
        mark = green("[PASS]") if ok else red("[FAIL]")
        print(f"    {mark} {check}")
    if r["suggestions"]:
        print("\n  " + bold("Suggestions:"))
        for s in r["suggestions"]:
            print(f"    - {yellow(s)}")
    else:
        print("\n  " + green("Excellent! This password follows all best practices."))
    print(bold("-" * 57))


def option_check():
    pwd = read_password("\nEnter password to check (input hidden): ")
    if not pwd:
        print(red("Password cannot be empty."))
        return
    result = analyse_password(pwd)
    show_report(pwd, result)
    save_history({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "password": mask(pwd),
        "length": result["length"],
        "score": result["score"],
        "rating": result["rating"],
    })


def option_generate():
    print("\n  a. Random password (strongest)")
    print("  b. Passphrase (easier to remember)")
    choice = input("Choose a or b: ").strip().lower()
    if choice == "a":
        raw = input("Length (12-64, default 16): ").strip()
        length = int(raw) if raw.isdigit() else 16
        if not 12 <= length <= 64:
            print(yellow("Length out of range, using 16."))
            length = 16
        pwd = generate_password(length)
    elif choice == "b":
        pwd = generate_passphrase()
    else:
        print(red("Invalid choice."))
        return
    r = analyse_password(pwd)
    print("\n  Generated : " + green(bold(pwd)))
    print(f"  Score     : {r['score']}/100  ({r['rating']})")
    print(f"  Entropy   : {r['entropy']} bits")
    print(f"  Crack time: {r['crack_time']}")


def option_hash():
    pwd = read_password("\nEnter a password to hash (input hidden): ")
    if not pwd:
        print(red("Password cannot be empty."))
        return
    sha, (s1, h1), (s2, h2) = hash_demo(pwd)
    print("\n" + bold("1) Plain SHA-256 (fast, unsalted - NOT safe for storage)"))
    print(f"   {sha}")
    print("   Same password always gives the same hash, so attackers")
    print("   can use pre-computed 'rainbow tables' to reverse it.")
    print("\n" + bold("2) PBKDF2-HMAC-SHA256, 100,000 rounds + random salt (SAFE)"))
    print(f"   Run 1  salt: {s1}")
    print(f"          hash: {h1[:48]}...")
    print(f"   Run 2  salt: {s2}")
    print(f"          hash: {h2[:48]}...")
    print(green("   Same password, different salt -> completely different hashes."))
    print(green("   Slow + salted hashing makes brute-force attacks impractical."))


def option_audit():
    path = input("\nEnter file name (one password per line): ").strip()
    try:
        with open(path, "r", encoding="utf-8") as f:
            passwords = [line.rstrip("\n") for line in f if line.strip()]
    except FileNotFoundError:
        print(red(f"File '{path}' not found."))
        return
    if not passwords:
        print(yellow("The file is empty."))
        return

    print("\n" + bold(f"{'No.':<5}{'Password':<28}{'Len':>4}{'Score':>7}   Rating"))
    print("-" * 58)
    counts = {}
    total = 0
    for i, pwd in enumerate(passwords, 1):
        r = analyse_password(pwd)
        counts[r["rating"]] = counts.get(r["rating"], 0) + 1
        total += r["score"]
        paint = RATING_COLOURS[r["rating"]]
        print(f"{i:<5}{mask(pwd)[:26]:<28}{r['length']:>4}{r['score']:>7}   {paint(r['rating'])}")
    print("-" * 58)
    print(bold("Summary:"))
    print(f"  Passwords audited : {len(passwords)}")
    print(f"  Average score     : {total / len(passwords):.1f}/100")
    for rating in ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]:
        if rating in counts:
            print(f"  {rating:<18}: {counts[rating]}")
    weak = counts.get("Very Weak", 0) + counts.get("Weak", 0)
    if weak:
        print(red(f"  {weak} password(s) need to be changed immediately!"))


def option_history():
    history = load_history()
    if not history:
        print(yellow("\nNo history yet. Check a password first."))
        return
    print("\n" + bold(f"{'Date & Time':<21}{'Password':<22}{'Score':>6}   Rating"))
    print("-" * 62)
    for h in history[-10:]:                               # last 10 entries
        paint = RATING_COLOURS.get(h["rating"], str)
        print(f"{h['time']:<21}{h['password'][:20]:<22}{h['score']:>6}   {paint(h['rating'])}")
    print(f"\n(Showing {min(10, len(history))} of {len(history)} entries. "
          "Only masked passwords are stored.)")


def main():
    print_header()
    actions = {"1": option_check, "2": option_generate, "3": option_hash,
               "4": option_audit, "5": option_history}
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-6): ").strip()
        if choice == "6":
            print(cyan("\nStay safe online. Goodbye!"))
            break
        action = actions.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print(yellow("\nCancelled."))
        else:
            print(red("Invalid choice. Please enter a number from 1 to 6."))


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(cyan("\nGoodbye!"))
