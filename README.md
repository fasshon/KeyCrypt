# 🔐 KeyCrypt: Encrypted C++ Password Manager

**KeyCrypt** is a simple password manager built in C++ using the Crypto++ library. It securely stores passwords using AES encryption in CBC mode, protecting sensitive credentials like website logins.  

## 📦 Features

- AES encryption (CBC mode) using the Crypto++ library
- Account system (username and password)
- Password file storage with per-entry encryption
- Secure IV and key generation
- Console-based UI for saving and retrieving passwords

---

## ⚙️ How It Works

- On first run, `KeyCrypt` will:
  - Ask the user to create a username/password
  - Generate a key and IV (saved to `key.key` and `iv.key`)
  - Store encrypted login credentials in `account.key`
- On subsequent runs:
  - It checks for existing keys and credentials
  - Authenticates the user by decrypting and verifying input
- After login:
  - Users can store new passwords (website + encrypted password)
  - Or read existing saved passwords

---

## 🗂️ File Structure

| File Name       | Purpose                                |
|----------------|----------------------------------------|
| `main.cpp`     | Main logic and UI loop                 |
| `account.key`  | Stores encrypted username & password   |
| `passwords.key`| Stores encrypted website passwords     |
| `key.key`      | AES encryption key                     |
| `iv.key`       | AES initialization vector              |
| `information.txt` | Stores user's name                  |

---

## 🛠️ Dependencies

- **Crypto++ Library**
  - Ensure Crypto++ is installed:
    - On Linux: `sudo apt install libcrypto++-dev libcrypto++-doc libcrypto++-utils`
    - On macOS (with Homebrew): `brew install cryptopp`

---

## 🚀 Compilation

Use `g++` or any C++17+ compatible compiler with Crypto++:

```bash
g++ main.cpp -o keycrypt -lcryptopp
