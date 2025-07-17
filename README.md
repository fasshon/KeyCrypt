# KeyCrypt

A simple command-line password manager in C++ using Crypto++ for AES-256 encryption (CBC mode).

## Features

- AES-256 encryption with random key and IV
- Salted encryption for user credentials and stored passwords
- User login with password and security question fallback
- Add and view encrypted passwords stored in a file
- Persistent keys and data storage

## Usage

1. On first run, create your account with username, password, and security question.
2. Login with your credentials or answer your security question after 3 failed attempts.
3. Use the menu to add new passwords or view saved ones.

## Building

Requires Crypto++ installed.

Compile with:
```bash
g++ -std=c++17 main.cpp -lcryptopp -pthread -o keycrypt
