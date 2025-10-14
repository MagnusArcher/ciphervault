import pyperclip


def copy_to_clipboard(text):
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def ask_copy(text, item_name="text"):
    try:
        choice = input(f"\n📋 Copy {item_name} to clipboard? (y/n): ").strip().lower()
        
        if choice == 'y':
            if copy_to_clipboard(text):
                print(f"✅ {item_name.capitalize()} copied to clipboard!")
                return True
            else:
                print(f"❌ Failed to copy to clipboard")
                return False
        else:
            print(f"⏭️  Skipped copying {item_name}")
            return False
    except (KeyboardInterrupt, EOFError):
        print("\n")
        return False
