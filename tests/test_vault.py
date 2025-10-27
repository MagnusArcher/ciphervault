import pytest
import os
from modules.vault import save_password_to_vault, load_vault, vault_exists

def test_vault_save_load():
    master_password = "MasterPass123!"
    name = "Test Account"
    password = "TestPass456!"
    
    assert save_password_to_vault(master_password, name, password)
    
    entries = load_vault(master_password)
    assert len(entries) == 1
    assert entries[0]['name'] == name
    assert entries[0]['password'] == password
    
    if os.path.exists("vault.json"):
        os.remove("vault.json")

def test_vault_empty():
    entries = load_vault("wrong_password")
    assert entries == []
