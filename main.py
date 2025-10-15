#!/usr/bin/env python3

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, Input, Label, Select
from textual.screen import Screen, ModalScreen
from textual.binding import Binding

from modules.password_gen import generate_password
from modules.password_check import check_password_strength
from modules.encryptor import encrypt_text
from modules.decryptor import decrypt_text
from modules.clipboard_utils import ask_copy, copy_to_clipboard


class MessageModal(ModalScreen):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("enter", "dismiss", "Close"),
    ]
    
    def __init__(self, title: str, message: str, message_type: str = "info"):
        super().__init__()
        self.modal_title = title
        self.modal_message = message
        self.message_type = message_type
    
    def compose(self) -> ComposeResult:
        style_map = {
            "success": "green",
            "error": "red",
            "info": "blue",
            "warning": "yellow"
        }
        style = style_map.get(self.message_type, "blue")
        
        with Container(id="message_modal"):
            yield Static(f"[bold {style}]{self.modal_title}[/bold {style}]", classes="modal_title")
            yield Static(self.modal_message, classes="modal_message")
            yield Button("OK", variant="primary", id="modal_ok")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()


class MainMenuScreen(Screen):
    BINDINGS = [
        Binding("1", "generate", "Generate Password"),
        Binding("2", "check", "Check Password"),
        Binding("3", "encrypt", "Encrypt Text"),
        Binding("4", "decrypt", "Decrypt Text"),
        Binding("q", "quit", "Quit"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="main_container"):
            yield Static("[bold cyan]🔐 CipherVault v1.0[/bold cyan]", classes="app_title")
            yield Static("[dim]Your Secure Text Toolkit[/dim]", classes="app_subtitle")
            
            with Vertical(id="menu_buttons"):
                yield Button("🎲 Generate Strong Password", id="btn_generate", variant="primary")
                yield Button("🔍 Check Password Strength", id="btn_check", variant="success")
                yield Button("🔒 Encrypt Text", id="btn_encrypt", variant="warning")
                yield Button("🔓 Decrypt Text", id="btn_decrypt", variant="error")
                yield Button("❌ Exit", id="btn_exit")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_generate":
            self.app.push_screen(GeneratePasswordScreen())
        elif event.button.id == "btn_check":
            self.app.push_screen(CheckPasswordScreen())
        elif event.button.id == "btn_encrypt":
            self.app.push_screen(EncryptTextScreen())
        elif event.button.id == "btn_decrypt":
            self.app.push_screen(DecryptTextScreen())
        elif event.button.id == "btn_exit":
            self.app.exit()
    
    def action_generate(self) -> None:
        self.app.push_screen(GeneratePasswordScreen())
    
    def action_check(self) -> None:
        self.app.push_screen(CheckPasswordScreen())
    
    def action_encrypt(self) -> None:
        self.app.push_screen(EncryptTextScreen())
    
    def action_decrypt(self) -> None:
        self.app.push_screen(DecryptTextScreen())
    
    def action_quit(self) -> None:
        self.app.exit()


class GeneratePasswordScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with ScrollableContainer(id="gen_container"):
            yield Static("[bold]🎲 Password Generator[/bold]", classes="screen_title")
            
            with Vertical(classes="form_section"):
                yield Label("Password Length (8-64):")
                yield Input(placeholder="16", id="input_length", value="16")
                
                yield Label("")
                yield Static("[bold]Character Types:[/bold]")
                
                yield Horizontal(
                    Static("Include Lowercase (a-z): ", classes="checkbox_label"),
                    Button("✓ Yes", id="chk_lower", variant="success"),
                    classes="checkbox_row"
                )
                
                yield Horizontal(
                    Static("Include Uppercase (A-Z): ", classes="checkbox_label"),
                    Button("✓ Yes", id="chk_upper", variant="success"),
                    classes="checkbox_row"
                )
                
                yield Horizontal(
                    Static("Include Digits (0-9): ", classes="checkbox_label"),
                    Button("✓ Yes", id="chk_digits", variant="success"),
                    classes="checkbox_row"
                )
                
                yield Horizontal(
                    Static("Include Symbols (!@#...): ", classes="checkbox_label"),
                    Button("✓ Yes", id="chk_symbols", variant="success"),
                    classes="checkbox_row"
                )
            
            with Horizontal(classes="button_row"):
                yield Button("Generate", id="btn_gen_submit", variant="primary")
                yield Button("Back", id="btn_gen_back")
            
            yield Static("", id="gen_result")
        
        yield Footer()
    
    def __init__(self):
        super().__init__()
        self.use_lower = True
        self.use_upper = True
        self.use_digits = True
        self.use_symbols = True
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "chk_lower":
            self.use_lower = not self.use_lower
            event.button.label = "✓ Yes" if self.use_lower else "✗ No"
            event.button.variant = "success" if self.use_lower else "default"
        
        elif event.button.id == "chk_upper":
            self.use_upper = not self.use_upper
            event.button.label = "✓ Yes" if self.use_upper else "✗ No"
            event.button.variant = "success" if self.use_upper else "default"
        
        elif event.button.id == "chk_digits":
            self.use_digits = not self.use_digits
            event.button.label = "✓ Yes" if self.use_digits else "✗ No"
            event.button.variant = "success" if self.use_digits else "default"
        
        elif event.button.id == "chk_symbols":
            self.use_symbols = not self.use_symbols
            event.button.label = "✓ Yes" if self.use_symbols else "✗ No"
            event.button.variant = "success" if self.use_symbols else "default"
        
        elif event.button.id == "btn_gen_submit":
            self.generate()
        
        elif event.button.id == "btn_gen_back":
            self.app.pop_screen()
    
    def generate(self):
        try:
            length_input = self.query_one("#input_length", Input)
            length = int(length_input.value)
            
            if length < 8 or length > 64:
                self.app.push_screen(MessageModal("Error", "Length must be between 8 and 64!", "error"))
                return
            
            if not (self.use_lower or self.use_upper or self.use_digits or self.use_symbols):
                self.app.push_screen(MessageModal("Error", "Select at least one character type!", "error"))
                return
            
            password = generate_password(length, self.use_lower, self.use_upper, self.use_digits, self.use_symbols)
            strength = check_password_strength(password)
            
            result_widget = self.query_one("#gen_result", Static)
            
            result_text = f"""
[bold green]✅ Password Generated Successfully![/bold green]

[bold white on blue] {password} [/bold white on blue]

📊 [bold]Strength Analysis:[/bold]
  🔒 Level: [bold green]{strength['level']}[/bold green]
  📏 Length: {strength['length']} characters
  🔢 Entropy: ~{strength['entropy']:.0f} bits
  
✓ Lowercase: {"Yes" if strength['has_lower'] else "No"}
✓ Uppercase: {"Yes" if strength['has_upper'] else "No"}
✓ Digits: {"Yes" if strength['has_digit'] else "No"}
✓ Symbols: {"Yes" if strength['has_symbol'] else "No"}
"""
            
            if copy_to_clipboard(password):
                result_text += "\n📋 [bold green]Copied to clipboard![/bold green]"
            
            result_widget.update(result_text)
        
        except ValueError:
            self.app.push_screen(MessageModal("Error", "Invalid length! Please enter a number.", "error"))
    
    def action_back(self) -> None:
        self.app.pop_screen()


class CheckPasswordScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with ScrollableContainer(id="check_container"):
            yield Static("[bold]🔍 Password Strength Checker[/bold]", classes="screen_title")
            
            with Vertical(classes="form_section"):
                yield Label("Enter password to check:")
                yield Input(placeholder="Enter your password...", id="input_password", password=False)
            
            with Horizontal(classes="button_row"):
                yield Button("Check Strength", id="btn_check_submit", variant="primary")
                yield Button("Back", id="btn_check_back")
            
            yield Static("", id="check_result")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_check_submit":
            self.check()
        elif event.button.id == "btn_check_back":
            self.app.pop_screen()
    
    def check(self):
        password_input = self.query_one("#input_password", Input)
        password = password_input.value
        
        if not password:
            self.app.push_screen(MessageModal("Error", "Please enter a password!", "error"))
            return
        
        result = check_password_strength(password)
        
        strength_colors = {
            "Weak": "red",
            "Medium": "yellow",
            "Strong": "green",
            "Very Strong": "bright_green"
        }
        
        color = strength_colors.get(result['level'], "white")
        
        result_text = f"""
[bold]📊 Password Strength Analysis[/bold]

Password: [dim]{password}[/dim]

[bold {color}]Overall Strength: {result['level']}[/bold {color}]

📏 Length: {result['length']} characters
🔢 Entropy: ~{result['entropy']:.0f} bits

Character Types:
  {'✓' if result['has_lower'] else '✗'} Lowercase letters (a-z)
  {'✓' if result['has_upper'] else '✗'} Uppercase letters (A-Z)
  {'✓' if result['has_digit'] else '✗'} Digits (0-9)
  {'✓' if result['has_symbol'] else '✗'} Special symbols (!@#...)
"""
        
        if result['suggestions']:
            result_text += "\n[bold yellow]💡 Suggestions:[/bold yellow]\n"
            for suggestion in result['suggestions']:
                result_text += f"  • {suggestion}\n"
        
        result_widget = self.query_one("#check_result", Static)
        result_widget.update(result_text)
    
    def action_back(self) -> None:
        self.app.pop_screen()


class EncryptTextScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with ScrollableContainer(id="encrypt_container"):
            yield Static("[bold]🔒 Text Encryption[/bold]", classes="screen_title")
            
            with Vertical(classes="form_section"):
                yield Label("Enter text to encrypt:")
                yield Input(placeholder="Your secret message...", id="input_plaintext")
                
                yield Label("")
                
                yield Horizontal(
                    Static("Use random key: ", classes="checkbox_label"),
                    Button("✓ Yes", id="chk_random_key", variant="success"),
                    classes="checkbox_row"
                )
                
                yield Label("Or enter your own key (min 8 characters):")
                yield Input(placeholder="Leave empty for random key", id="input_enc_key", password=True, disabled=True)
            
            with Horizontal(classes="button_row"):
                yield Button("Encrypt", id="btn_enc_submit", variant="primary")
                yield Button("Back", id="btn_enc_back")
            
            yield Static("", id="encrypt_result")
        
        yield Footer()
    
    def __init__(self):
        super().__init__()
        self.use_random_key = True
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "chk_random_key":
            self.use_random_key = not self.use_random_key
            event.button.label = "✓ Yes" if self.use_random_key else "✗ No"
            event.button.variant = "success" if self.use_random_key else "default"
            
            key_input = self.query_one("#input_enc_key", Input)
            key_input.disabled = self.use_random_key
        
        elif event.button.id == "btn_enc_submit":
            self.encrypt()
        
        elif event.button.id == "btn_enc_back":
            self.app.pop_screen()
    
    def encrypt(self):
        plaintext_input = self.query_one("#input_plaintext", Input)
        plaintext = plaintext_input.value
        
        if not plaintext:
            self.app.push_screen(MessageModal("Error", "Please enter text to encrypt!", "error"))
            return
        
        key = None
        if not self.use_random_key:
            key_input = self.query_one("#input_enc_key", Input)
            key = key_input.value
            
            if len(key) < 8:
                self.app.push_screen(MessageModal("Error", "Key must be at least 8 characters!", "error"))
                return
        
        try:
            result = encrypt_text(plaintext, key)
            
            result_text = f"""
[bold green]✅ Encryption Successful![/bold green]

📝 [bold]Original Text:[/bold]
[dim]{plaintext}[/dim]

🔑 [bold]Encryption Key:[/bold]
[bold yellow on black] {result['key']} [/bold yellow on black]
[red]⚠ Save this key! You'll need it for decryption![/red]

📦 [bold]Encrypted Text:[/bold]
[dim]{result['encrypted']}[/dim]
"""
            
            copy_to_clipboard(result['key'])
            result_text += "\n📋 [bold green]Key copied to clipboard![/bold green]"
            
            result_widget = self.query_one("#encrypt_result", Static)
            result_widget.update(result_text)
        
        except Exception as e:
            self.app.push_screen(MessageModal("Error", f"Encryption failed: {str(e)}", "error"))
    
    def action_back(self) -> None:
        self.app.pop_screen()


class DecryptTextScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with ScrollableContainer(id="decrypt_container"):
            yield Static("[bold]🔓 Text Decryption[/bold]", classes="screen_title")
            
            with Vertical(classes="form_section"):
                yield Label("Enter encrypted text:")
                yield Input(placeholder="Paste encrypted text here...", id="input_encrypted")
                
                yield Label("Enter decryption key:")
                yield Input(placeholder="Your encryption key...", id="input_dec_key", password=True)
            
            with Horizontal(classes="button_row"):
                yield Button("Decrypt", id="btn_dec_submit", variant="primary")
                yield Button("Back", id="btn_dec_back")
            
            yield Static("", id="decrypt_result")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_dec_submit":
            self.decrypt()
        elif event.button.id == "btn_dec_back":
            self.app.pop_screen()
    
    def decrypt(self):
        encrypted_input = self.query_one("#input_encrypted", Input)
        key_input = self.query_one("#input_dec_key", Input)
        
        encrypted = encrypted_input.value
        key = key_input.value
        
        if not encrypted or not key:
            self.app.push_screen(MessageModal("Error", "Both encrypted text and key are required!", "error"))
            return
        
        result = decrypt_text(encrypted, key)
        
        if result['success']:
            result_text = f"""
[bold green]✅ Decryption Successful![/bold green]

📄 [bold]Original Text:[/bold]
[bold white on blue] {result['decrypted']} [/bold white on blue]
"""
            
            if copy_to_clipboard(result['decrypted']):
                result_text += "\n📋 [bold green]Text copied to clipboard![/bold green]"
            
            result_widget = self.query_one("#decrypt_result", Static)
            result_widget.update(result_text)
        else:
            self.app.push_screen(MessageModal("Decryption Failed", result['error'], "error"))
    
    def action_back(self) -> None:
        self.app.pop_screen()


class CipherVaultApp(App):
    CSS = """
    Screen {
        align: center middle;
    }
    
    #main_container {
        width: 80;
        height: auto;
        border: heavy $primary;
        background: $surface;
        padding: 2;
    }
    
    .app_title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .app_subtitle {
        text-align: center;
        margin-bottom: 2;
    }
    
    #menu_buttons {
        width: 100%;
        height: auto;
        align: center middle;
    }
    
    #menu_buttons Button {
        width: 100%;
        margin: 1;
    }
    
    .screen_title {
        text-align: center;
        margin-bottom: 2;
        text-style: bold;
    }
    
    .form_section {
        width: 100%;
        padding: 1;
        border: solid $primary;
        background: $panel;
        margin-bottom: 1;
    }
    
    Label {
        margin-top: 1;
        margin-bottom: 0.5;
    }
    
    Input {
        width: 100%;
        margin-bottom: 1;
    }
    
    .checkbox_row {
        width: 100%;
        height: auto;
        margin: 0.5;
    }
    
    .checkbox_label {
        width: auto;
        padding-right: 2;
    }
    
    .button_row {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 2;
    }
    
    .button_row Button {
        margin: 0 1;
    }
    
    #gen_result, #check_result, #encrypt_result, #decrypt_result {
        margin-top: 2;
        padding: 2;
        border: solid $success;
        background: $panel;
        min-height: 10;
    }
    
    #message_modal {
        width: 60;
        height: auto;
        border: heavy $error;
        background: $surface;
        padding: 2;
        align: center middle;
    }
    
    .modal_title {
        text-align: center;
        margin-bottom: 2;
        text-style: bold;
    }
    
    .modal_message {
        text-align: center;
        margin-bottom: 2;
        padding: 1;
    }
    
    #modal_ok {
        width: 20;
    }
    
    ScrollableContainer {
        width: 100%;
        height: 100%;
        padding: 2;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]
    
    def on_mount(self) -> None:
        self.title = "CipherVault - Secure Text Toolkit"
        self.sub_title = "Python Encryption Tool"
        self.push_screen(MainMenuScreen())
    
    def action_quit(self) -> None:
        self.exit()


if __name__ == "__main__":
    app = CipherVaultApp()
    app.run()
