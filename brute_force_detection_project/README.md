# Brute-Force Attack Detection System

A medium-level, terminal-based cybersecurity project using **Python 3 + SQLite**. It demonstrates account protection against repeated password guesses.

## Features
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes with random salts, not plaintext.
- Three consecutive incorrect password attempts trigger a 60-second account lockout.
- A successful login resets the failed-attempt counter.
- Security events are recorded in a local SQLite database.
- Parameterized SQL queries are used for user input.

## Requirements
- Python 3.10 or newer (no third-party packages required)
- Linux/Kali Linux, macOS, or Windows terminal

## Run on Kali Linux / Linux
1. Extract the ZIP and open a terminal in the project folder.
2. Optional: create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Initialize the database:
   ```bash
   python3 main.py init
   ```
4. Register a demo user:
   ```bash
   python3 main.py register student1
   ```
   Type a password of at least 8 characters when prompted.
5. Try a correct login:
   ```bash
   python3 main.py login student1
   ```
6. Test detection: run `python3 main.py login student1` three times and enter an incorrect password each time. The third failure locks the account for 60 seconds.
7. Review the log:
   ```bash
   python3 main.py events
   ```

## Run on Windows
```powershell
py main.py init
py main.py register student1
py main.py login student1
py main.py events
```

## Important testing notes
- The lockout happens after **three incorrect passwords**, not after a correct login.
- After lockout expires, the attempt counter resets.
- Do not use a real personal password. This is an educational local demo, not a production authentication service.
- The optional `--password` command-line argument is convenient for quick tests, but command-line arguments may be visible in shell history/process lists. Prefer the secure prompt with no `--password` option.

## Project structure
```text
brute_force_detection_project/
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
└── test_project.py
```
The `security.db` file is created automatically at runtime and is excluded from version control.

## Suggested demonstration
1. Register `student1`.
2. Log in successfully and show `LOGIN_SUCCESS`.
3. Enter a wrong password three times.
4. Show the temporary lockout message.
5. Run `python3 main.py events` to show the recorded events.

## Limitations and future improvements
- The lockout is per username; a production system should also consider IP/device rate limiting, alerts, MFA, secure recovery, and carefully designed denial-of-service protections.
- This demo is local and terminal-based; it is not exposed to the internet and should not be used to protect real accounts.
