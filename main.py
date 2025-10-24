import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from prompt_toolkit import prompt
from prompt_toolkit.validation import Validator, ValidationError

from modules.password_gen import generate_password
from modules.password_check import check_password_strength
from modules.encryptor import encrypt_text
from modules.decryptor import decrypt_text
from modules.clipboard_utils import copy_to_clipboard

console = Console()

class LengthValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text.isdigit():
            raise ValidationError(message="Please enter a number.")
        value = int(text)
        if value < 8 or value > 64:
            raise ValidationError(message="Length must be between 8 and 64.")

class NonEmptyValidator(Validator):
    def validate(self, document):
        if not document.text.strip():
            raise ValidationError(message="This field cannot be empty.")

def clear_screen():
    console.clear()

def show_main_menu():
    title = Text("CipherVault v1.0", style="bold cyan")
    subtitle = Text("Your Secure Text Toolkit", style="dim")
    panel = Panel(
        f"{title}\n{subtitle}",
        title="Main Menu",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)
    console.print("[1] Generate Strong Password")
    console.print("[2] Check Password Strength")
    console.print("[3] Encrypt Text")
    console.print("[4] Decrypt Text")
    console.print("[5] Exit")
    console.print()

def get_menu_choice():
    try:
        choice = prompt("Select an option (1-5): ", validator=Validator.from_callable(
            lambda x: x in ['1','2','3','4','5'],
            error_message="Please enter 1, 2, 3, 4, or 5."
        ))
        return choice
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold red]Goodbye![/bold red]")
        sys.exit(0)

def generate_password_flow():
    console.print(Panel("Password Generator", style="bold green"))

    length = 16
    try:
        length_input = prompt("Password Length (8-64) [default: 16]: ", default="16")
        if length_input.strip():
            length = int(length_input)
            if length < 8 or length > 64:
                console.print("[red]Length must be between 8 and 64. Using default 16.[/red]")
                length = 16
    except ValueError:
        console.print("[red]Invalid input. Using default 16.[/red]")
        length = 16

    use_lower = prompt("Include lowercase (a-z)? (y/n) [y]: ", default="y").lower().startswith('y')
    use_upper = prompt("Include uppercase (A-Z)? (y/n) [y]: ", default="y").lower().startswith('y')
    use_digits = prompt("Include digits (0-9)? (y/n) [y]: ", default="y").lower().startswith('y')
    use_symbols = prompt("Include symbols (!@#...)? (y/n) [y]: ", default="y").lower().startswith('y')

    if not (use_lower or use_upper or use_digits or use_symbols):
        console.print("[red]At least one character type must be selected.[/red]")
        return

    try:
        password = generate_password(length, use_lower, use_upper, use_digits, use_symbols)
        strength = check_password_strength(password)

        result_table = Table(box=box.SIMPLE)
        result_table.add_column("Property", style="bold")
        result_table.add_column("Value")

        result_table.add_row("Generated Password", f"[bold white on blue]{password}[/bold white on blue]")
        result_table.add_row("Strength Level", f"[bold green]{strength['level']}[/bold green]")
        result_table.add_row("Length", str(strength['length']))
        result_table.add_row("Entropy (bits)", f"~{strength['entropy']:.0f}")
        result_table.add_row("Lowercase", "Yes" if strength['has_lower'] else "No")
        result_table.add_row("Uppercase", "Yes" if strength['has_upper'] else "No")
        result_table.add_row("Digits", "Yes" if strength['has_digit'] else "No")
        result_table.add_row("Symbols", "Yes" if strength['has_symbol'] else "No")

        console.print(Panel(result_table, title="[SUCCESS] Password Generated", border_style="green"))

        if prompt("Copy password to clipboard? (y/n): ", default="y").lower().startswith('y'):
            if copy_to_clipboard(password):
                console.print("[green][SUCCESS] Password copied to clipboard![/green]")
            else:
                console.print("[red][ERROR] Failed to copy to clipboard.[/red]")

        if strength['suggestions']:
            console.print("\n[bold yellow]Suggestions:[/bold yellow]")
            for s in strength['suggestions']:
                console.print(f"  - {s}")

    except Exception as e:
        console.print(f"[red][ERROR] {str(e)}[/red]")

def check_password_flow():
    console.print(Panel("Password Strength Checker", style="bold yellow"))
    try:
        password = prompt("Enter password to check: ", is_password=True, validator=NonEmptyValidator())
        result = check_password_strength(password)

        strength_colors = {
            "Weak": "red",
            "Medium": "yellow",
            "Strong": "green",
            "Very Strong": "bright_green"
        }
        color = strength_colors.get(result['level'], "white")

        result_table = Table(box=box.SIMPLE)
        result_table.add_column("Property", style="bold")
        result_table.add_column("Value")

        result_table.add_row("Password", f"[dim]{password}[/dim]")
        result_table.add_row("Overall Strength", f"[{color} bold]{result['level']}[/{color} bold]")
        result_table.add_row("Length", str(result['length']))
        result_table.add_row("Entropy (bits)", f"~{result['entropy']:.0f}")
        result_table.add_row("Lowercase", "Yes" if result['has_lower'] else "No")
        result_table.add_row("Uppercase", "Yes" if result['has_upper'] else "No")
        result_table.add_row("Digits", "Yes" if result['has_digit'] else "No")
        result_table.add_row("Symbols", "Yes" if result['has_symbol'] else "No")

        console.print(Panel(result_table, title="Password Analysis", border_style="yellow"))

        if result['suggestions']:
            console.print("\n[bold yellow]Suggestions:[/bold yellow]")
            for s in result['suggestions']:
                console.print(f"  - {s}")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[red][ERROR] {str(e)}[/red]")

def encrypt_text_flow():
    console.print(Panel("Text Encryption", style="bold magenta"))
    try:
        plaintext = prompt("Enter text to encrypt: ", validator=NonEmptyValidator())
        use_random = prompt("Use random key? (y/n) [y]: ", default="y").lower().startswith('y')

        key = None
        if not use_random:
            key = prompt("Enter your own key (min 8 chars): ", is_password=True, validator=Validator.from_callable(
                lambda x: len(x) >= 8,
                error_message="Key must be at least 8 characters."
            ))

        result = encrypt_text(plaintext, key)

        result_table = Table(box=box.SIMPLE)
        result_table.add_column("Item", style="bold")
        result_table.add_column("Value")

        result_table.add_row("Original Text", f"[dim]{plaintext}[/dim]")
        result_table.add_row("Encryption Key", f"[bold yellow on black]{result['key']}[/bold yellow on black]")
        result_table.add_row("Encrypted Text", f"[dim]{result['encrypted']}[/dim]")

        console.print(Panel(result_table, title="[SUCCESS] Encryption Successful", border_style="magenta"))
        console.print("[red]Save this key! You'll need it for decryption![/red]")

        if prompt("Copy key to clipboard? (y/n): ", default="y").lower().startswith('y'):
            if copy_to_clipboard(result['key']):
                console.print("[green][SUCCESS] Key copied to clipboard![/green]")
            else:
                console.print("[red][ERROR] Failed to copy key.[/red]")

        if prompt("Copy encrypted text to clipboard? (y/n): ", default="y").lower().startswith('y'):
            if copy_to_clipboard(result['encrypted']):
                console.print("[green][SUCCESS] Encrypted text copied to clipboard![/green]")
            else:
                console.print("[red][ERROR] Failed to copy encrypted text.[/red]")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[red][ERROR] {str(e)}[/red]")

def decrypt_text_flow():
    console.print(Panel("Text Decryption", style="bold blue"))
    try:
        encrypted = prompt("Enter encrypted text: ", validator=NonEmptyValidator())
        key = prompt("Enter decryption key: ", is_password=True, validator=NonEmptyValidator())

        result = decrypt_text(encrypted, key)

        if result['success']:
            result_table = Table(box=box.SIMPLE)
            result_table.add_column("Decrypted Text", style="bold white on blue")
            result_table.add_row(result['decrypted'])

            console.print(Panel(result_table, title="[SUCCESS] Decryption Successful", border_style="blue"))

            if prompt("Copy decrypted text to clipboard? (y/n): ", default="y").lower().startswith('y'):
                if copy_to_clipboard(result['decrypted']):
                    console.print("[green][SUCCESS] Decrypted text copied to clipboard![/green]")
                else:
                    console.print("[red][ERROR] Failed to copy decrypted text.[/red]")
        else:
            console.print(f"[red][Decryption Failed] {result['error']}[/red]")

    except (KeyboardInterrupt, EOFError):
        return
    except Exception as e:
        console.print(f"[red][ERROR] {str(e)}[/red]")

def main():
    while True:
        clear_screen()
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
            console.print("[bold cyan]Goodbye![/bold cyan]")
            break

        try:
            prompt("\nPress Enter to return to main menu...")
        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    main()
