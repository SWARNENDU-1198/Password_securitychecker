# Password Security Checker

A menu-driven Python command-line tool that analyses password strength, generates strong passwords, demonstrates secure password hashing and audits a file of passwords.

It uses only the Python standard library, so there is nothing to install.

![Strength check](screenshots/01_start_and_weak_password.png)

## Features

| Option | What it does |
| --- | --- |
| 1. Check password strength | Hidden input, 12 security checks, score out of 100, rating, entropy, crack-time estimate and suggestions |
| 2. Generate a strong password | Random password (12–64 characters) or a memorable passphrase, using the `secrets` module |
| 3. Hashing demo | Plain SHA-256 compared with salted PBKDF2-HMAC-SHA256 (100,000 rounds) |
| 4. Audit passwords from a file | Rates every password in a text file (one per line) and prints a summary |
| 5. View check history | Last 10 checks; only masked passwords are ever stored |

### What it detects

- Exact common or leaked passwords (`123456`, `password`, `qwerty`)
- Common words with tweaks (`P@ssw0rd`, `Summer2024!`, `india@123`)
- Sequences (`abc`, `123`), keyboard patterns (`qwer`, `asdf`), repeated characters (`aaa`) and years

## Run

```bash
python password_checker.py
```

Requires Python 3.8+. Try option 4 with the included `sample_passwords.txt`.

## How scoring works

- **Points** are given for length (≥ 8, ≥ 12, ≥ 16), lowercase, uppercase, digits, symbols and character variety.
- **Penalties** are taken off for predictable patterns. An exact common password is capped at 5.
- **Rating:** 0–29 Very Weak, 30–49 Weak, 50–69 Moderate, 70–84 Strong, 85–100 Very Strong.
- **Entropy** is `length × log2(pool size)`, minus 10 bits for each pattern found.
- **Crack time** assumes an offline attack at 10 billion guesses per second.

## Project structure

```
password_checker.py       # the application
sample_passwords.txt      # sample input for the audit option
screenshots/              # output screenshots
docs/                     # project documentation (PDF)
```

## Security notes

- Passwords are read with `getpass`, so they are not shown on screen.
- The history file stores masked passwords only (for example `S*********!`).
- Generated passwords use `secrets` (cryptographically secure), not `random`.

---

Built for TA-2 Python Application Development, B.Tech–M.Tech (Integrated) CSE, Cyber Security, NFSU Dharwad.
