import sys
import json
import argparse
import os
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from prompt_toolkit import prompt
from prompt_toolkit.validation import Validator, ValidationError

from modules.password_gen import generate_password
from modules.password_check import check_password_strength
from modules.encryptor import encrypt_text, encrypt_file
from modules.decryptor import decrypt_text, decrypt_file
from modules.clipboard_utils import copy_to_clipboard
from modules.vault import save_password_to_vault, load_vault, vault_exists

console = Console()

logging.basicConfig(
    filename='cipher.log',
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("cipher")

CONFIG_FILE = "config.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        'cipher': 'AES-GCM',
        'kdf': 'PBKDF2',
        'hash': 'SHA256'
    }

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

CONFIG = load_config()

class LengthValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text.isdigit():
            raise ValidationError(message="[ERROR] Please enter a number.")
        value = int(text)
        if value < 8 or value > 64:
            raise ValidationError(message="[ERROR] Length must be between 8 and 64.")

class NonEmptyValidator(Validator):
    def validate(self, document):
        if not document.text.strip():
            raise ValidationError(message="[ERROR] This field cannot be empty.")

def clear_screen():
    console.clear()

def show_banner():
    title = Text("CipherVault", style="bold cyan")
    subtitle = Text("Your Secure Text & Password Toolkit", style="dim")
    console.print(Panel(
        title + "\n" + subtitle,
        border_style="blue",
        padding=(1, 2),
        title="[bold yellow]v1.1[/bold yellow]",
        subtitle="[dim]GPLv3 Licensed • Advanced Crypto Options[/dim]"
    ))

def show_main_menu():
    table = Table(show_header=False, box=box.SIMPLE, expand=False)
    table.add_column("Option", style="bold green", width=4)
    table.add_column("Action", style="bold white")
    table.add_row("[1]", "Generate Strong Password")
    table.add_row("[2]", "Check Password Strength")
    table.add_row("[3]", "Encrypt Text")
    table.add_row("[4]", "Decrypt Text")
    table.add_row("[5]", "Encrypt File")
    table.add_row("[6]", "Decrypt File")
    table.add_row("[7]", "Configuration")
    table.add_row("[8]", "Save Password")
    table.add_row("[9]", "View Saved Passwords")
    table.add_row("[10]", "Exit")
    console.print(Panel(table, title="Main Menu", border_style="green", padding=(1, 2)))

def get_menu_choice():
    try:
        choice = prompt("\n➤ Select an option (1-10): ", validator=Validator.from_callable(
            lambda x: x in [str(i) for i in range(1, 11)],
            error_message="[ERROR] Please enter 1-10."
        ))
        return choice
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold red]Goodbye![/bold red]")
        sys.exit(0)

def configuration_menu():
    console.print("\n", end="")
    console.print(Panel("[bold]Configuration[/bold]", style="bold purple", border_style="purple"))
    
    core_table = Table(box=box.ROUNDED, show_header=False)
    core_table.add_column("Setting", style="bold cyan", width=15)
    core_table.add_column("Value")
    core_table.add_row("Cipher", CONFIG['cipher'])
    core_table.add_row("KDF", CONFIG['kdf'])
    core_table.add_row("Hash", CONFIG['hash'])
    console.print(Panel(core_table, title="Core Settings", border_style="cyan"))
    
    vault_table = Table(box=box.ROUNDED, show_header=False)
    vault_table.add_column("Setting", style="bold magenta", width=20)
    vault_table.add_column("Value")
    vault_table.add_row("KDF", "Argon2id (🔒 Enforced)")
    vault_table.add_row("Hash", "SHA-512 (🔒 Enforced)")
    vault_table.add_row("Nonce", "16 bytes (🔒 Enforced)")
    vault_table.add_row("Key Wrapping", "ChaCha20 (🔒 Enforced)")
    vault_table.add_row("Auto-lock", "Immediate (🔒 Enforced)")
    console.print(Panel(vault_table, title="Password Vault Security Policy", border_style="red"))
    
    console.print("[red][WARNING] Vault always uses the strongest available algorithms for maximum security.[/red]")
    console.print("[red]These settings cannot be changed to ensure your passwords remain protected.[/red]")
    
    cipher_choice = prompt("\nCipher (1=AES-GCM, 2=ChaCha20) [1]: ", default="1")
    CONFIG['cipher'] = "ChaCha20" if cipher_choice == "2" else "AES-GCM"
    
    kdf_choice = prompt("KDF (1=PBKDF2, 2=Argon2) [1]: ", default="1")
    CONFIG['kdf'] = "Argon2" if kdf_choice == "2" else "PBKDF2"
    
    if CONFIG['kdf'] == "PBKDF2":
        hash_choice = prompt("Hash (1=SHA256, 2=SHA512) [1]: ", default="1")
        CONFIG['hash'] = "SHA512" if hash_choice == "2" else "SHA256"
    
    save_config(CONFIG)
    logger.info("Configuration updated")
    console.print("[SUCCESS] Configuration updated!")
    prompt("\n➤ Press Enter to return...")

def generate_password_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]Password Generator[/bold]", style="bold green", border_style="green"))

    length_input = prompt("Password Length (8-64): ")
    try:
        length = int(length_input)
        if length < 8 or length > 64:
            console.print("[ERROR] Length must be between 8 and 64.")
            return
    except ValueError:
        console.print("[ERROR] Invalid number.")
        return

    use_lower = prompt("Include lowercase (a-z)? (y/n): ").lower().startswith('y')
    use_upper = prompt("Include uppercase (A-Z)? (y/n): ").lower().startswith('y')
    use_digits = prompt("Include digits (0-9)? (y/n): ").lower().startswith('y')
    use_symbols = prompt("Include symbols (!@#...)? (y/n): ").lower().startswith('y')

    if not (use_lower or use_upper or use_digits or use_symbols):
        console.print("[ERROR] At least one character type must be selected.")
        return

    try:
        password = generate_password(length, use_lower, use_upper, use_digits, use_symbols)
        strength = check_password_strength(password)

        result_table = Table(box=box.ROUNDED, show_header=False)
        result_table.add_column("Property", style="bold cyan", width=20)
        result_table.add_column("Value")
        result_table.add_row("Generated Password", f"[bold white on blue]{password}[/bold white on blue]")
        result_table.add_row("Strength Level", f"[bold {strength['level'].lower()}]{strength['level']}[/bold {strength['level'].lower()}]")
        result_table.add_row("Length", str(strength['length']))
        result_table.add_row("Entropy (bits)", f"~{strength['entropy']:.0f}")
        result_table.add_row("Lowercase", "Yes" if strength['has_lower'] else "No")
        result_table.add_row("Uppercase", "Yes" if strength['has_upper'] else "No")
        result_table.add_row("Digits", "Yes" if strength['has_digit'] else "No")
        result_table.add_row("Symbols", "Yes" if strength['has_symbol'] else "No")
        console.print(Panel(result_table, title="[SUCCESS] Password Generated", border_style="green", padding=(1, 2)))

        if prompt("\n➤ Copy password to clipboard? (y/n): ").lower().startswith('y'):
            if copy_to_clipboard(password):
                console.print("[SUCCESS] Password copied to clipboard!")
                logger.info("Password copied to clipboard")
            else:
                console.print("[yellow][WARNING] Clipboard failed. Copy manually:[/yellow]")
                console.print(f"[bold white on blue]{password}[/bold white on blue]")
                logger.info("Clipboard failed")

        if strength['suggestions']:
            console.print("\n[bold yellow]Suggestions for Improvement:[/bold yellow]")
            for s in strength['suggestions']:
                console.print(f"  • {s}")
        
        logger.info(f"Password generated (length={length})")

    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"Password generation failed: {str(e)}")

def check_password_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]Password Strength Checker[/bold]", style="bold yellow", border_style="yellow"))
    try:
        password = prompt("Enter password to check: ", is_password=False, validator=NonEmptyValidator())
        result = check_password_strength(password)

        strength_colors = {"Weak": "red", "Medium": "yellow", "Strong": "green", "Very Strong": "bright_green"}
        color = strength_colors.get(result['level'], "white")
        masked_pw = "*" * len(password)

        result_table = Table(box=box.ROUNDED, show_header=False)
        result_table.add_column("Property", style="bold cyan", width=20)
        result_table.add_column("Value")
        result_table.add_row("Password", f"[dim]{masked_pw}[/dim]")
        result_table.add_row("Overall Strength", f"[{color} bold]{result['level']}[/{color} bold]")
        result_table.add_row("Length", str(result['length']))
        result_table.add_row("Entropy (bits)", f"~{result['entropy']:.0f}")
        result_table.add_row("Lowercase", "Yes" if result['has_lower'] else "No")
        result_table.add_row("Uppercase", "Yes" if result['has_upper'] else "No")
        result_table.add_row("Digits", "Yes" if result['has_digit'] else "No")
        result_table.add_row("Symbols", "Yes" if result['has_symbol'] else "No")
        console.print(Panel(result_table, title="Password Analysis", border_style="yellow", padding=(1, 2)))

        if result['suggestions']:
            console.print("\n[bold yellow]Suggestions:[/bold yellow]")
            for s in result['suggestions']:
                console.print(f"  • {s}")
        
        logger.info(f"Password checked (length={result['length']}, strength={result['level']})")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"Password check failed: {str(e)}")

def encrypt_text_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]Text Encryption[/bold]", style="bold magenta", border_style="magenta"))
    try:
        plaintext = prompt("Enter text to encrypt: ", validator=NonEmptyValidator())
        use_random = prompt("Use random key? (y/n): ").lower().startswith('y')

        key = None
        if not use_random:
            key = prompt("Enter your own key (min 8 chars): ", is_password=False, validator=Validator.from_callable(
                lambda x: len(x) >= 8,
                error_message="[ERROR] Key must be at least 8 characters."
            ))

        result = encrypt_text(plaintext, key, cipher=CONFIG['cipher'], kdf=CONFIG['kdf'], hash_alg=CONFIG['hash'])

        result_table = Table(box=box.ROUNDED, show_header=False)
        result_table.add_column("Item", style="bold cyan", width=20)
        result_table.add_column("Value")
        result_table.add_row("Original Text", f"[dim]{plaintext}[/dim]")
        result_table.add_row("Encryption Key", f"[bold yellow on black]{result['key']}[/bold yellow on black]")
        result_table.add_row("Encrypted Text", f"[dim]{result['encrypted']}[/dim]")
        result_table.add_row("Cipher", result['cipher'])
        result_table.add_row("KDF", result['kdf'])
        if result['kdf'] == 'PBKDF2':
            result_table.add_row("Hash", result['hash'])
        console.print(Panel(result_table, title="[SUCCESS] Encryption Successful", border_style="magenta", padding=(1, 2)))
        console.print("[WARNING] Save this key! You'll need it for decryption!")

        if prompt("\n➤ Copy key to clipboard? (y/n): ").lower().startswith('y'):
            if copy_to_clipboard(result['key']):
                console.print("[SUCCESS] Key copied to clipboard!")
                logger.info("Encryption key copied to clipboard")
            else:
                console.print("[yellow][WARNING] Clipboard failed. Copy manually:[/yellow]")
                console.print(f"[bold yellow on black]{result['key']}[/bold yellow on black]")
                logger.info("Clipboard failed for key")

        if prompt("➤ Copy encrypted text to clipboard? (y/n): ").lower().startswith('y'):
            if copy_to_clipboard(result['encrypted']):
                console.print("[SUCCESS] Encrypted text copied to clipboard!")
                logger.info("Encrypted text copied to clipboard")
            else:
                console.print("[yellow][WARNING] Clipboard failed. Copy manually:[/yellow]")
                console.print(f"[dim]{result['encrypted']}[/dim]")
                logger.info("Clipboard failed for encrypted text")
        
        logger.info(f"Text encrypted (cipher={result['cipher']}, kdf={result['kdf']})")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"Text encryption failed: {str(e)}")

def decrypt_text_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]Text Decryption[/bold]", style="bold blue", border_style="blue"))
    try:
        encrypted = prompt("Enter encrypted text: ", validator=NonEmptyValidator())
        key = prompt("Enter decryption key: ", is_password=False, validator=NonEmptyValidator())

        result = decrypt_text(encrypted, key, cipher=CONFIG['cipher'], kdf=CONFIG['kdf'], hash_alg=CONFIG['hash'])

        if result['success']:
            result_table = Table(box=box.ROUNDED, show_header=False)
            result_table.add_column("Decrypted Text", style="bold white on blue")
            result_table.add_row(result['decrypted'])
            console.print(Panel(result_table, title="[SUCCESS] Decryption Successful", border_style="blue", padding=(1, 2)))
            if prompt("\n➤ Copy decrypted text to clipboard? (y/n): ").lower().startswith('y'):
                if copy_to_clipboard(result['decrypted']):
                    console.print("[SUCCESS] Decrypted text copied to clipboard!")
                    logger.info("Decrypted text copied to clipboard")
                else:
                    console.print("[yellow][WARNING] Clipboard failed. Copy manually:[/yellow]")
                    console.print(f"[bold white on blue]{result['decrypted']}[/bold white on blue]")
                    logger.info("Clipboard failed for decrypted text")
            logger.info("Text decrypted successfully")
        else:
            console.print(f"[ERROR] Decryption Failed: {result['error']}")
            logger.error(f"Text decryption failed: {result['error']}")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"Text decryption failed: {str(e)}")

def encrypt_file_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]File Encryption[/bold]", style="bold magenta", border_style="magenta"))
    try:
        input_path = prompt("Enter input file path: ", validator=NonEmptyValidator())
        output_path = prompt("Enter output file path: ", validator=NonEmptyValidator())
        use_random = prompt("Use random key? (y/n): ").lower().startswith('y')

        key = None
        if not use_random:
            key = prompt("Enter your own key (min 8 chars): ", is_password=False, validator=Validator.from_callable(
                lambda x: len(x) >= 8,
                error_message="[ERROR] Key must be at least 8 characters."
            ))

        result = encrypt_file(input_path, output_path, key, cipher=CONFIG['cipher'], kdf=CONFIG['kdf'], hash_alg=CONFIG['hash'])

        result_table = Table(box=box.ROUNDED, show_header=False)
        result_table.add_column("Item", style="bold cyan", width=20)
        result_table.add_column("Value")
        result_table.add_row("Input File", input_path)
        result_table.add_row("Output File", output_path)
        result_table.add_row("Encryption Key", f"[bold yellow on black]{result['key']}[/bold yellow on black]")
        result_table.add_row("Cipher", result['cipher'])
        result_table.add_row("KDF", result['kdf'])
        if result['kdf'] == 'PBKDF2':
            result_table.add_row("Hash", result['hash'])
        console.print(Panel(result_table, title="[SUCCESS] File Encrypted", border_style="magenta", padding=(1, 2)))
        console.print("[WARNING] Save this key! You'll need it for decryption!")

        if prompt("\n➤ Copy key to clipboard? (y/n): ").lower().startswith('y'):
            if copy_to_clipboard(result['key']):
                console.print("[SUCCESS] Key copied to clipboard!")
                logger.info("File encryption key copied to clipboard")
            else:
                console.print("[yellow][WARNING] Clipboard failed. Copy manually:[/yellow]")
                console.print(f"[bold yellow on black]{result['key']}[/bold yellow on black]")
                logger.info("Clipboard failed for file key")
        
        logger.info(f"File encrypted (input={input_path}, output={output_path})")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"File encryption failed: {str(e)}")

def decrypt_file_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]File Decryption[/bold]", style="bold blue", border_style="blue"))
    try:
        input_path = prompt("Enter encrypted file path: ", validator=NonEmptyValidator())
        output_path = prompt("Enter output file path: ", validator=NonEmptyValidator())
        key = prompt("Enter decryption key: ", is_password=False, validator=NonEmptyValidator())

        result = decrypt_file(input_path, output_path, key, cipher=CONFIG['cipher'], kdf=CONFIG['kdf'], hash_alg=CONFIG['hash'])

        if result['success']:
            console.print("[SUCCESS] File decrypted successfully!")
            console.print(f"Output saved to: [bold]{output_path}[/bold]")
            logger.info(f"File decrypted (input={input_path}, output={output_path})")
        else:
            console.print(f"[ERROR] Decryption Failed: {result['error']}")
            logger.error(f"File decryption failed: {result['error']}")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"File decryption failed: {str(e)}")

def save_password_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]Save Password to Vault[/bold]", style="bold green", border_style="green"))
    try:
        password = prompt("Enter password to save: ", validator=NonEmptyValidator())
        name = prompt("Enter a name for this password (e.g., Gmail): ", validator=NonEmptyValidator())
        
        master_password = prompt("Enter your Master Password (min 8 chars): ", is_password=True, validator=Validator.from_callable(
            lambda x: len(x) >= 8,
            error_message="[ERROR] Master Password must be at least 8 characters."
        ))
        
        if save_password_to_vault(master_password, name, password):
            console.print("[SUCCESS] Password saved to vault!")
        else:
            console.print("[ERROR] Failed to save password to vault.")
        
        logger.info(f"Password saved to vault: {name}")
        
    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"Save password to vault failed: {str(e)}")

def view_vault_flow():
    console.print("\n", end="")
    console.print(Panel("[bold]Saved Passwords[/bold]", style="bold yellow", border_style="yellow"))
    try:
        if not vault_exists():
            console.print("[INFO] No passwords saved yet.")
            return
        
        master_password = prompt("Enter your Master Password: ", is_password=True, validator=NonEmptyValidator())
        entries = load_vault(master_password)
        
        if not entries:
            console.print("[ERROR] Failed to load vault. Incorrect Master Password?")
            return
        
        if not entries:
            console.print("[INFO] Vault is empty.")
            return
        
        for i, entry in enumerate(entries, 1):
            console.print(f"\n[bold]{i}. {entry['name']}[/bold]")
            console.print(f"   Password: [bold white on blue]{entry['password']}[/bold white on blue]")
            console.print(f"   Created: {entry['created_at']}")
            
            if prompt(f"\n➤ Copy password for '{entry['name']}' to clipboard? (y/n): ").lower().startswith('y'):
                if copy_to_clipboard(entry['password']):
                    console.print("[SUCCESS] Password copied to clipboard!")
                    logger.info(f"Vault password copied: {entry['name']}")
                else:
                    console.print("[yellow][WARNING] Clipboard failed. Copy manually:[/yellow]")
                    console.print(f"[bold white on blue]{entry['password']}[/bold white on blue]")
                    logger.info("Clipboard failed for vault password")
        
        logger.info("Vault viewed successfully")
        
    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[ERROR] {str(e)}")
        logger.error(f"View vault failed: {str(e)}")

def parse_args():
    parser = argparse.ArgumentParser(description="CipherVault: Secure Text & Password Toolkit")
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    subparsers = parser.add_subparsers(dest='command')
    
    gen_parser = subparsers.add_parser('generate', help='Generate a strong password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length (8-64)')
    gen_parser.add_argument('--no-lower', action='store_true', help='Exclude lowercase')
    gen_parser.add_argument('--no-upper', action='store_true', help='Exclude uppercase')
    gen_parser.add_argument('--no-digits', action='store_true', help='Exclude digits')
    gen_parser.add_argument('--no-symbols', action='store_true', help='Exclude symbols')
    
    check_parser = subparsers.add_parser('check', help='Check password strength')
    check_parser.add_argument('password', help='Password to check')
    
    enc_parser = subparsers.add_parser('encrypt', help='Encrypt text')
    enc_parser.add_argument('text', help='Text to encrypt')
    enc_parser.add_argument('--key', help='Encryption key (min 8 chars)')
    enc_parser.add_argument('--random-key', action='store_true', help='Use random key')
    
    dec_parser = subparsers.add_parser('decrypt', help='Decrypt text')
    dec_parser.add_argument('encrypted', help='Encrypted text')
    dec_parser.add_argument('key', help='Decryption key')
    
    encf_parser = subparsers.add_parser('encrypt-file', help='Encrypt a file')
    encf_parser.add_argument('input', help='Input file path')
    encf_parser.add_argument('output', help='Output file path')
    encf_parser.add_argument('--key', help='Encryption key (min 8 chars)')
    encf_parser.add_argument('--random-key', action='store_true', help='Use random key')
    
    decf_parser = subparsers.add_parser('decrypt-file', help='Decrypt a file')
    decf_parser.add_argument('input', help='Encrypted file path')
    decf_parser.add_argument('output', help='Output file path')
    decf_parser.add_argument('key', help='Decryption key')
    
    return parser.parse_args()

def main():
    args = parse_args()
    
    if args.command:
        if args.command == 'generate':
            use_lower = not args.no_lower
            use_upper = not args.no_upper
            use_digits = not args.no_digits
            use_symbols = not args.no_symbols
            try:
                password = generate_password(args.length, use_lower, use_upper, use_digits, use_symbols)
                if args.json:
                    print(json.dumps({'password': password, 'strength': check_password_strength(password)}, indent=2))
                else:
                    print(password)
                logger.info(f"Password generated via CLI (length={args.length})")
            except Exception as e:
                if args.json:
                    print(json.dumps({'error': str(e)}, indent=2))
                else:
                    print(f"[ERROR] {str(e)}")
                logger.error(f"CLI password generation failed: {str(e)}")
        elif args.command == 'check':
            try:
                result = check_password_strength(args.password)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Strength: {result['level']}")
                logger.info(f"Password checked via CLI (length={len(args.password)})")
            except Exception as e:
                if args.json:
                    print(json.dumps({'error': str(e)}, indent=2))
                else:
                    print(f"[ERROR] {str(e)}")
                logger.error(f"CLI password check failed: {str(e)}")
        elif args.command == 'encrypt':
            try:
                result = encrypt_text(args.text, args.key, use_random=args.random_key)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print(result['encrypted'])
                logger.info(f"Text encrypted via CLI (cipher={result['cipher']})")
            except Exception as e:
                if args.json:
                    print(json.dumps({'error': str(e)}, indent=2))
                else:
                    print(f"[ERROR] {str(e)}")
                logger.error(f"CLI text encryption failed: {str(e)}")
        elif args.command == 'decrypt':
            try:
                result = decrypt_text(args.encrypted, args.key)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    if result['success']:
                        print(result['decrypted'])
                    else:
                        print(f"[ERROR] {result['error']}")
                logger.info("Text decrypted via CLI")
            except Exception as e:
                if args.json:
                    print(json.dumps({'error': str(e)}, indent=2))
                else:
                    print(f"[ERROR] {str(e)}")
                logger.error(f"CLI text decryption failed: {str(e)}")
        elif args.command == 'encrypt-file':
            try:
                result = encrypt_file(args.input, args.output, args.key, use_random=args.random_key)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print("File encrypted successfully")
                logger.info(f"File encrypted via CLI (input={args.input})")
            except Exception as e:
                if args.json:
                    print(json.dumps({'error': str(e)}, indent=2))
                else:
                    print(f"[ERROR] {str(e)}")
                logger.error(f"CLI file encryption failed: {str(e)}")
        elif args.command == 'decrypt-file':
            try:
                result = decrypt_file(args.input, args.output, args.key)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    if result['success']:
                        print("File decrypted successfully")
                    else:
                        print(f"[ERROR] {result['error']}")
                logger.info("File decrypted via CLI")
            except Exception as e:
                if args.json:
                    print(json.dumps({'error': str(e)}, indent=2))
                else:
                    print(f"[ERROR] {str(e)}")
                logger.error(f"CLI file decryption failed: {str(e)}")
        return
    
    while True:
        clear_screen()
        show_banner()
        show_main_menu()
        choice = get_menu_choice()

        if choice == '1':
            generate_password_flow()
        elif choice == '2':
            check_password_flow()
        elif choice == '3':
            encrypt_text_flow()
        elif choice == '4':
            decrypt_text_flow()
        elif choice == '5':
            encrypt_file_flow()
        elif choice == '6':
            decrypt_file_flow()
        elif choice == '7':
            configuration_menu()
        elif choice == '8':
            save_password_flow()
        elif choice == '9':
            view_vault_flow()
        elif choice == '10':
            console.print("[bold cyan]Goodbye! Stay secure![/bold cyan]")
            logger.info("Application exited")
            break

        try:
            prompt("\n➤ Press Enter to return to main menu...")
        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    main()
