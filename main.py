#!/usr/bin/env python3

import sys
from modules.password_gen import generate_password
from modules.password_check import check_password_strength
from modules.encryptor import encrypt_text
from modules.decryptor import decrypt_text


def print_banner():
    print("\n" + "="*40)
    print("       🔐 CipherVault v1.0")
    print("   Your Secure Text Toolkit")
    print("="*40 + "\n")


def print_menu():
    print("\n[1] Generate Strong Password")
    print("[2] Check Password Strength")
    print("[3] Encrypt Text")
    print("[4] Decrypt Text")
    print("[5] Exit\n")


def get_choice():
    try:
        choice = input("Choose an option (1-5): ").strip()
        return choice
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)


def handle_password_generation():
    print("\n" + "━"*40)
    print("🎲 Password Generator")
    print("━"*40 + "\n")
    
    try:
        length = int(input("Password length (8-64): "))
        if length < 8 or length > 64:
            print("❌ Error: Length must be between 8 and 64")
            return
        
        use_lower = input("Include lowercase letters? (y/n): ").lower() == 'y'
        use_upper = input("Include uppercase letters? (y/n): ").lower() == 'y'
        use_digits = input("Include digits? (y/n): ").lower() == 'y'
        use_symbols = input("Include symbols? (y/n): ").lower() == 'y'
        
        if not (use_lower or use_upper or use_digits or use_symbols):
            print("❌ Error: At least one character type must be selected")
            return
        
        password = generate_password(length, use_lower, use_upper, use_digits, use_symbols)
        
        print("\n✅ Generated Password:")
        print(f"   {password}\n")
        
        strength = check_password_strength(password)
        print(f"🔒 Strength: {strength['level']}")
        
    except ValueError:
        print("❌ Error: Invalid input")
    except KeyboardInterrupt:
        print("\n\nCancelled.")


def handle_password_check():
    print("\n" + "━"*40)
    print("🔍 Password Strength Checker")
    print("━"*40 + "\n")
    
    try:
        password = input("Enter password to check: ")
        
        if not password:
            print("❌ Error: Password cannot be empty")
            return
        
        result = check_password_strength(password)
        
        print("\n" + "━"*40)
        print("📊 Password Strength Analysis")
        print("━"*40)
        print(f"Length: {result['length']} characters")
        print(f"Lowercase: {'✓' if result['has_lower'] else '✗'}")
        print(f"Uppercase: {'✓' if result['has_upper'] else '✗'}")
        print(f"Digits: {'✓' if result['has_digit'] else '✗'}")
        print(f"Symbols: {'✓' if result['has_symbol'] else '✗'}")
        print(f"Entropy: ~{result['entropy']:.0f} bits")
        print(f"\nOverall Strength: {result['level']}")
        
        if result['suggestions']:
            print("\n💡 Suggestions:")
            for suggestion in result['suggestions']:
                print(f"  - {suggestion}")
        
        print("━"*40)
        
    except KeyboardInterrupt:
        print("\n\nCancelled.")


def handle_encryption():
    print("\n" + "━"*40)
    print("🔒 Text Encryption")
    print("━"*40 + "\n")
    
    try:
        text = input("Enter text to encrypt: ")
        
        if not text:
            print("❌ Error: Text cannot be empty")
            return
        
        use_random = input("Use random key? (y/n): ").lower() == 'y'
        
        if use_random:
            key = None
        else:
            key = input("Enter encryption key (min 8 characters): ")
            if len(key) < 8:
                print("❌ Error: Key must be at least 8 characters")
                return
        
        result = encrypt_text(text, key)
        
        print("\n✅ Encryption successful!\n")
        print("🔑 Key (save this!):")
        print(f"   {result['key']}\n")
        print("📦 Encrypted text:")
        print(f"   {result['encrypted']}\n")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    except KeyboardInterrupt:
        print("\n\nCancelled.")


def handle_decryption():
    print("\n" + "━"*40)
    print("🔓 Text Decryption")
    print("━"*40 + "\n")
    
    try:
        encrypted = input("Enter encrypted text: ")
        key = input("Enter decryption key: ")
        
        if not encrypted or not key:
            print("❌ Error: Both encrypted text and key are required")
            return
        
        result = decrypt_text(encrypted, key)
        
        if result['success']:
            print("\n✅ Decryption successful!\n")
            print("📄 Original text:")
            print(f"   {result['decrypted']}\n")
        else:
            print(f"\n❌ Decryption failed: {result['error']}\n")
        
    except KeyboardInterrupt:
        print("\n\nCancelled.")


def main():
    print_banner()
    
    while True:
        print_menu()
        choice = get_choice()
        
        if choice == '1':
            handle_password_generation()
        elif choice == '2':
            handle_password_check()
        elif choice == '3':
            handle_encryption()
        elif choice == '4':
            handle_decryption()
        elif choice == '5':
            print("\n👋 Thank you for using CipherVault!\n")
            sys.exit(0)
        else:
            print("\n❌ Invalid option. Please choose 1-5.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!\n")
        sys.exit(0)
