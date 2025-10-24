import pyperclip

def copy_to_clipboard(text):
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False
