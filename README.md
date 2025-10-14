# 🔐 CipherVault

**Your Secure Text & Password Toolkit**

A professional-grade command-line tool for password generation, strength analysis, and text encryption/decryption using AES-256.

---

## 🌟 Features

- 🎲 **Password Generator** - Create cryptographically secure random passwords
- 🔍 **Password Strength Checker** - Analyze password security level
- 🔒 **Text Encryption** - Encrypt text with AES-256-GCM
- 🔓 **Text Decryption** - Decrypt encrypted messages
- 💻 **CLI Interface** - Easy-to-use command-line menu
- 🛡️ **Secure** - Uses industry-standard cryptographic libraries

---

## 📋 Requirements

- Python 3.7+
- cryptography library

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/MagnusArcher/ciphervault.git
cd ciphervault
2. Install dependencies
Bash

pip install -r requirements.txt
3. Run the application
Bash

python main.py
🎯 Usage
Main Menu
text

╔════════════════════════════════════╗
║       🔐 CipherVault v1.0         ║
║   Your Secure Text Toolkit        ║
╚════════════════════════════════════╝

[1] Generate Strong Password
[2] Check Password Strength
[3] Encrypt Text
[4] Decrypt Text
[5] Exit
1. Password Generator
Generate cryptographically secure random passwords:

Customizable length (8-64 characters)
Choose character types (lowercase, uppercase, digits, symbols)
Uses secrets module for cryptographic randomness
Example:

text

Password length (8-64): 16
Include lowercase? (y/n): y
Include uppercase? (y/n): y
Include digits? (y/n): y
Include symbols? (y/n): y

✅ Generated Password: aK9$mP2@xL5#qR8!
🔒 Strength: Very Strong
2. Password Strength Checker
Analyze password security:

Length analysis
Character diversity check
Entropy calculation
Strength rating (Weak, Medium, Strong, Very Strong)
Improvement suggestions
Example:

text

Enter password to check: mypassword123

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Password Strength Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Length: 13 characters
Lowercase: ✓
Uppercase: ✗
Digits: ✓
Symbols: ✗
Entropy: ~51 bits

Overall Strength: Medium

💡 Suggestions:
  - Add uppercase letters
  - Add special symbols
  - Increase length to 16+ characters
3. Text Encryption
Encrypt sensitive text with AES-256-GCM:

Choose random key or provide your own
Secure key derivation (PBKDF2)
Authenticated encryption (GCM mode)
Base64 encoded output
Example:

text

Enter text to encrypt: Hello, World!
Use random key? (y/n): y

✅ Encryption successful!

🔑 Key (save this!): 
   MySecureKey12345

📦 Encrypted text:
   gAAAAABl1x2Y3R...K9m3pQ==
4. Text Decryption
Decrypt previously encrypted text:

Example:

text

Enter encrypted text: gAAAAABl1x2Y3R...K9m3pQ==
Enter decryption key: MySecureKey12345

✅ Decryption successful!

📄 Original text:
   Hello, World!
🛠 Technical Details
Encryption
Algorithm: AES-256-GCM (Galois/Counter Mode)
Key Derivation: PBKDF2-HMAC-SHA256
Iterations: 480,000 (OWASP recommendation 2023)
Salt: 16 bytes, randomly generated
Nonce: 12 bytes, randomly generated
Password Generation
Randomness Source: secrets module (CSPRNG)
Character Pool: Up to 94 characters
Entropy: ~6.5 bits per character (full pool)
Security Features
Cryptographically secure random number generation
Authenticated encryption (prevents tampering)
Proper key derivation
No hardcoded secrets
Memory-safe operations
📂 Project Structure
text

ciphervault/
├── README.md              # Documentation
├── LICENSE                # MIT License
├── .gitignore             # Git ignore rules
├── requirements.txt       # Python dependencies
├── main.py                # Main CLI application
└── modules/
    ├── __init__.py        # Package initialization
    ├── password_gen.py    # Password generator
    ├── password_check.py  # Password strength checker
    ├── encryptor.py       # Text encryption
    └── decryptor.py       # Text decryption
🎓 What I Learned
✅ Implementing secure password generation
✅ Password strength analysis algorithms
✅ AES-256-GCM encryption/decryption
✅ Key derivation functions (PBKDF2)
✅ Python cryptography library
✅ Modular code architecture
✅ CLI application design
🔮 Future Enhancements
 GUI interface
 File encryption/decryption
 Password manager functionality
 Multi-language support
 Export passwords to file
 Password history
🤝 Contributing
Contributions are welcome! Feel free to:

Report bugs
Suggest features
Submit pull requests
📝 License
MIT License - Copyright (c) 2025 Magnus Archer

See LICENSE for details.

👤 Author
Magnus Archer

GitHub: @MagnusArcher
Telegram: @MagnusArcher
Computer Science Student | Python & C++ Developer | Cybersecurity Enthusiast

⚠️ Disclaimer
This tool is for educational and personal use. Always follow best practices for password and data security. The author is not responsible for any misuse of this software.

<div align="center">
⭐ Star this project if you found it useful!

Secure your data with CipherVault 🔐

</div> ```
