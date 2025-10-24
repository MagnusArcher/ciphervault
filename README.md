# 🔐 CipherVault

**Your Secure Text & Password Toolkit**

A professional-grade command-line tool for password generation, strength analysis, and text encryption/decryption using AES-256-GCM with clipboard support.

---

## 🌟 Features

- **Password Generator** – Create cryptographically secure random passwords (8–64 chars)  
- **Password Strength Checker** – Analyze entropy, character diversity, and security level  
- **Text Encryption** – Encrypt with AES-256-GCM using PBKDF2 key derivation  
- **Text Decryption** – Securely decrypt previously encrypted messages  
- **Clipboard Support** – Copy passwords, keys, and encrypted text with confirmation  
- **Interactive CLI** – Clean, responsive, and user-friendly terminal interface  
- **Secure by Design** – No hardcoded secrets, proper salt/nonce, industry-standard crypto  

---

## 📋 Requirements

- Python 3.7+  
- `cryptography` (v41+)  
- `pyperclip`  
- `rich`  
- `prompt_toolkit`  

---

## 🚀 Installation

```bash
git clone https://github.com/MagnusArcher/ciphervault.git
cd ciphervault
pip install -r requirements.txt
python main.py
```

---

## 🎯 Usage

### Main Menu
```
[1] Generate Strong Password
[2] Check Password Strength
[3] Encrypt Text
[4] Decrypt Text
[5] Exit
```

### 1. Password Generator

Generate cryptographically secure random passwords:

- Customizable length (8–64 characters)  
- Choose character types (lowercase, uppercase, digits, symbols)  
- Uses `secrets` module for cryptographic randomness  
- Guaranteed character diversity  
- Strength analysis with entropy and suggestions  

**Example:**
```
Password length (8-64): 16
Include lowercase? (y/n): y
Include uppercase? (y/n): y
Include digits? (y/n): y
Include symbols? (y/n): y

[SUCCESS] Password Generated Successfully!

 aK9$mP2@xL5#qR8! 

Strength Analysis:
  Level: Very Strong
  Length: 16 characters
  Entropy: ~104 bits
  Lowercase: Yes
  Uppercase: Yes
  Digits: Yes
  Symbols: Yes

Copy password to clipboard? (y/n): y
[SUCCESS] Password copied to clipboard!
```

### 2. Password Strength Checker

Analyze password security:

- Length analysis  
- Character diversity check  
- Entropy calculation (~bits)  
- Strength rating: Weak / Medium / Strong / Very Strong  
- Actionable improvement suggestions  

**Example:**
```
Enter password to check: mypassword123

Password Strength Analysis

Password: mypassword123

[Medium] Overall Strength: Medium

Length: 13 characters
Entropy: ~51 bits

Character Types:
  Yes Lowercase letters (a-z)
  No  Uppercase letters (A-Z)
  Yes Digits (0-9)
  No  Special symbols (!@#...)

Suggestions:
  - Add uppercase letters (A-Z)
  - Add special symbols (!@#$%^&*...)
  - Increase length to 16+ characters for better security
```

### 3. Text Encryption

Encrypt sensitive text with AES-256-GCM:

- Option for random key or custom key (min 8 chars)  
- Secure key derivation via PBKDF2-HMAC-SHA256 (480,000 iterations)  
- Authenticated encryption (GCM mode prevents tampering)  
- Base64-encoded output  
- Key and ciphertext copied to clipboard on request  

**Example:**
```
Enter text to encrypt: Hello, World!

[SUCCESS] Encryption Successful!

Original Text:
Hello, World!

Encryption Key:
 MySecureKey12345 
Save this key! You'll need it for decryption!

Encrypted Text:
gAAAAABl1x2Y3R...K9m3pQ==

Copy key to clipboard? (y/n): y
[SUCCESS] Key copied to clipboard!
Copy encrypted text to clipboard? (y/n): y
[SUCCESS] Encrypted text copied to clipboard!
```

### 4. Text Decryption

Decrypt previously encrypted text:

**Example:**
```
Enter encrypted text: gAAAAABl1x2Y3R...K9m3pQ==
Enter decryption key: MySecureKey12345

[SUCCESS] Decryption Successful!

Original Text:
 Hello, World! 

Copy decrypted text to clipboard? (y/n): y
[SUCCESS] Decrypted text copied to clipboard!
```

---

## 🛠 Technical Details

### Encryption

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)  
- **Key Derivation**: PBKDF2-HMAC-SHA256  
- **Iterations**: 480,000 (OWASP recommendation 2023)  
- **Salt**: 16 bytes, randomly generated per encryption  
- **Nonce**: 12 bytes, randomly generated per encryption  
- **Output**: Base64-encoded (salt + nonce + ciphertext)  

### Password Generation

- **Randomness Source**: `secrets` module (CSPRNG)  
- **Character Pool**: Up to 94 printable ASCII characters  
- **Entropy**: ~6.5 bits per character (full pool)  
- **Diversity Guarantee**: At least one character from each selected type  

### Clipboard Support

- **Library**: `pyperclip`  
- **Cross-platform**: Windows, Linux, macOS  
- **User Control**: Explicit confirmation before copy  
- **Error Handling**: Graceful fallback if clipboard unavailable  

### Security Features

- Cryptographically secure random number generation  
- Authenticated encryption (prevents tampering and replay)  
- Proper key derivation with high iteration count  
- No hardcoded secrets or keys  
- Memory-safe operations (no plaintext logging)  
- Secure clipboard interactions  

---

## 📂 Project Structure

```
ciphervault/
├── README.md                    # Documentation (this file)
├── LICENSE                      # GNU GPL v3.0 License
├── .gitignore                   # Git ignore rules
├── requirements.txt             # Python dependencies
├── main.py                      # CLI entry point (Rich + Prompt Toolkit)
└── modules/
    ├── __init__.py              # Package initialization
    ├── password_gen.py          # Secure password generation
    ├── password_check.py        # Password strength analysis
    ├── encryptor.py             # AES-256-GCM encryption
    ├── decryptor.py             # AES-256-GCM decryption
    └── clipboard_utils.py       # Cross-platform clipboard
```

---

## 🎓 What I Learned

- ✅ Implementing cryptographically secure password generation  
- ✅ Designing password strength analysis with entropy calculation  
- ✅ AES-256-GCM encryption and decryption with proper key derivation  
- ✅ Using PBKDF2-HMAC-SHA256 for secure key stretching  
- ✅ Building modular, maintainable Python architecture  
- ✅ Creating user-friendly CLI with Rich and Prompt Toolkit  
- ✅ Cross-platform clipboard integration  
- ✅ Applying security best practices in real-world code  

---

## 🔮 Future Enhancements

- [ ] GUI interface (Tkinter or PyQt)  
- [ ] File encryption/decryption support  
- [ ] Password manager with encrypted storage  
- [ ] Multi-language support  
- [ ] Export passwords to encrypted file  
- [ ] Password history and search  
- [ ] Batch encryption mode  
- [ ] Command-line arguments (non-interactive mode)  

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs  
- Suggest features  
- Submit pull requests  

Please ensure your code follows the existing style and includes appropriate error handling.

---

## 📝 License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

> This is **free software**: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for full terms.

---

## 👤 Author

**Magnus Archer**

- GitHub: [@MagnusArcher](https://github.com/MagnusArcher)  
- Telegram: [@MagnusArcher](https://t.me/MagnusArcher)  

*Computer Science Student | Python & C++ Developer | Cybersecurity Enthusiast*

---

## ⚠️ Disclaimer

This tool is for educational and personal use. Always follow best practices for password and data security. The author is not responsible for any misuse of this software.

---

<div align="center">

**⭐ Star this project if you found it useful!**  
*Secure your data with CipherVault* 🔐

</div>
