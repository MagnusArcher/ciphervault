#!/usr/bin/env python3

import sys
from modules.password_gen import generate_password
from modules.password_check import check_password_strength
from modules.encryptor import encrypt_text
from modules.decryptor import decrypt_text
from modules.clipboard_utils import ask_copy


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
    except (KeyboardInterrupt, EOFError):
        print("\n\nExiting...")
        sys.exit(0)


def get_input(prompt):
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print("\n\nCancelled.")
        return None


def handle_password_generation():
    print("\n" + "━"*40)
    print("🎲 Password Generator")
    print("━"*40 + "\n")
    
    try:
        length_input = get_input("Password length (8-64): ")
        if length_input is None:
            return
        
        length = int(length_input)
        if length < 8 or length > 64:
            print("❌ Error: Length must be between 8 and 64")
            return
        
        use_lower_input = get_input("Include lowercase letters? (y/n): ")
        if use_lower_input is None:
            return
        use_lower = use_lower_input.lower() == 'y'
        
        use_upper_input = get_input("Include uppercase letters? (y/n): ")
        if use_upper_input is None:
            return
        use_upper = use_upper_input.lower() == 'y'
        
        use_digits_input = get_input("Include digits? (y/n): ")
        if use_digits_input is None:
            return
        use_digits = use_digits_input.lower() == 'y'
        
        use_symbols_input = get_input("Include symbols? (y/n): ")
        if use_symbols_input is None:
            return
        use_symbols = use_symbols_input.lower() == 'y'
        
        if not (use_lower or use_upper or use_digits or use_symbols):
            print("❌ Error: At least one character type must be selected")
            return
        
        password = generate_password(length, use_lower, use_upper, use_digits, use_symbols)
        
        print("\n✅ Generated Password:")
        print(f"   {password}\n")
        
        strength = check_password_strength(password)
        print(f"🔒 Strength: {strength['level']}")
        
        ask_copy(password, "password")
        
    except ValueError:
        print("❌ Error: Invalid input")


def handle_password_check():
    print("\n" + "━"*40)
    print("🔍 Password Strength Checker")
    print("━"*40 + "\n")
    
    password = get_input("Enter password to check: ")
    if password is None:
        return
    
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


def handle_encryption():
    print("\n" + "━"*40)
    print("🔒 Text Encryption")
    print("━"*40 + "\n")
    
    text = get_input("Enter text to encrypt: ")
    if text is None:
        return
    
    if not text:
        print("❌ Error: Text cannot be empty")
        return
    
    print("\n📝 Original text:")
    print(f"   {text}")
    
    ask_copy(text, "original text")
    
    use_random_input = get_input("\nUse random key? (y/n): ")
    if use_random_input is None:
        return
    use_random = use_random_input.lower() == 'y'
    
    if use_random:
        key = None
    else:
        key = get_input("Enter encryption key (min 8 characters): ")
        if key is None:
            return
        if len(key) < 8:
            print("❌ Error: Key must be at least 8 characters")
            return
    
    try:
        result = encrypt_text(text, key)
        
        print("\n✅ Encryption successful!\n")
        
        print("🔑 Key (save this!):")
        print(f"   {result['key']}")
        
        ask_copy(result['key'], "encryption key")
        
        print("\n📦 Encrypted text:")
        print(f"   {result['encrypted']}")
        
        ask_copy(result['encrypted'], "encrypted text")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")


def handle_decryption():
    print("\n" + "━"*40)
    print("🔓 Text Decryption")
    print("━"*40 + "\n")
    
    encrypted = get_input("Enter encrypted text: ")
    if encrypted is None:
        return
    
    key = get_input("Enter decryption key: ")
    if key is None:
        return
    
    if not encrypted or not key:
        print("❌ Error: Both encrypted text and key are required")
        return
    
    result = decrypt_text(encrypted, key)
    
    if result['success']:
        print("\n✅ Decryption successful!\n")
        
        print("📄 Original text:")
        print(f"   {result['decrypted']}")
        
        ask_copy(result['decrypted'], "decrypted text")
    else:
        print(f"\n❌ Decryption failed: {result['error']}\n")


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
    except (KeyboardInterrupt, EOFError):
        print("\n\n👋 Goodbye!\n")
        sys.exit(0)
