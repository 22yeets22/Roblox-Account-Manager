# Roblox-Account-Manager

A fast, practical way to manage multiple Roblox accounts from a single interface without constantly logging in and out.

## Project Info
- Language: Python 3.8+
- GUI: PyQt5
- Platform: Windows
- Supports multiple accounts
- Multi-instance Roblox support
- Password hashing: Argon2

## Features
- One-click login for any saved Roblox account
- Store and manage multiple accounts in one place
- Secure credential storage using Argon2 hashing
- Launch and run multiple Roblox instances simultaneously
- Built-in Settings panel
- Integrated FAQ covering tokens, setup, and common issues
- Improved alerts and error handling with clear messages
- Clean and responsive PyQt5 interface

## Usage
1. Run the GUI:
   `python gui.py`
2. Add your Roblox accounts.
   Token instructions are documented in the FAQ.
3. Click an account to log in instantly.
4. For multiple clients at once, run this before gui.py:
   `python multi.py`

## Notes
- Windows-only due to Roblox limitations.
- Credentials are never stored in plain text, Argon2 is used for password hashing.
- Multi-instance support depends on your Roblox installation but works in most setups.
- Alerts are designed to be explicit so failures are obvious.

## License
MIT License. Use it, modify it, ship it.
