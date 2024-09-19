import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet

# Encryption and Decryption Functions

def caesar_cipher_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            base = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - base + shift_amount) % 26 + base)
        else:
            result += char
    return result

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def vigenere_cipher_encrypt(text, key):
    result = ""
    key = key.upper()
    key_length = len(key)
    key_int = [ord(i) for i in key]
    text_int = [ord(i) for i in text.upper()]
    for i in range(len(text_int)):
        value = (text_int[i] + key_int[i % key_length]) % 26
        result += chr(value + 65)
    return result

def vigenere_cipher_decrypt(text, key):
    result = ""
    key = key.upper()
    key_length = len(key)
    key_int = [ord(i) for i in key]
    text_int = [ord(i) for i in text.upper()]
    for i in range(len(text_int)):
        value = (text_int[i] - key_int[i % key_length] + 26) % 26
        result += chr(value + 65)
    return result

def generate_key():
    return Fernet.generate_key()

def aes_encrypt(text, key):
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text.decode()

def aes_decrypt(encrypted_text, key):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
    return decrypted_text

# GUI Application
class EncryptionTool(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Encryption Tool")
        self.geometry("500x350")
        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self)

        self.encrypt_tab = ttk.Frame(self.tab_control)
        self.decrypt_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.encrypt_tab, text="Encrypt")
        self.tab_control.add(self.decrypt_tab, text="Decrypt")
        self.tab_control.pack(expand=1, fill="both")

        # Encryption Tab
        self.encrypt_label = tk.Label(self.encrypt_tab, text="Enter Text:")
        self.encrypt_label.pack(pady=5)
        
        self.encrypt_text = tk.Entry(self.encrypt_tab, width=50)
        self.encrypt_text.pack(pady=5)

        self.cipher_type = tk.StringVar(value="caesar")
        self.cipher_options = ttk.Combobox(self.encrypt_tab, textvariable=self.cipher_type, values=["caesar", "vigenere", "aes"], state='readonly')
        self.cipher_options.pack(pady=5)
        self.cipher_options.set("caesar")  # Default value

        self.key_label = tk.Label(self.encrypt_tab, text="Key/Shift:")
        self.key_label.pack(pady=5)
        
        self.key_entry = tk.Entry(self.encrypt_tab, width=50)
        self.key_entry.pack(pady=5)

        self.encrypt_button = tk.Button(self.encrypt_tab, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack(pady=5)

        self.encrypted_message_label = tk.Label(self.encrypt_tab, text="Encrypted Message:")
        self.encrypted_message_label.pack(pady=5)
        
        self.encrypted_message = tk.Text(self.encrypt_tab, height=4, width=50, wrap=tk.WORD, state='disabled')
        self.encrypted_message.pack(pady=5)

        # Decryption Tab
        self.decrypt_label = tk.Label(self.decrypt_tab, text="Enter Encrypted Text:")
        self.decrypt_label.pack(pady=5)
        
        self.decrypt_text = tk.Entry(self.decrypt_tab, width=50)
        self.decrypt_text.pack(pady=5)

        self.cipher_type_decrypt = tk.StringVar(value="caesar")
        self.cipher_options_decrypt = ttk.Combobox(self.decrypt_tab, textvariable=self.cipher_type_decrypt, values=["caesar", "vigenere", "aes"], state='readonly')
        self.cipher_options_decrypt.pack(pady=5)
        self.cipher_options_decrypt.set("caesar")  # Default value

        self.key_label_decrypt = tk.Label(self.decrypt_tab, text="Key/Shift:")
        self.key_label_decrypt.pack(pady=5)
        
        self.key_entry_decrypt = tk.Entry(self.decrypt_tab, width=50)
        self.key_entry_decrypt.pack(pady=5)

        self.decrypt_button = tk.Button(self.decrypt_tab, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack(pady=5)

        self.decrypted_message_label = tk.Label(self.decrypt_tab, text="Decrypted Message:")
        self.decrypted_message_label.pack(pady=5)
        
        self.decrypted_message = tk.Text(self.decrypt_tab, height=4, width=50, wrap=tk.WORD, state='disabled')
        self.decrypted_message.pack(pady=5)

    def encrypt_message(self):
        text = self.encrypt_text.get()
        cipher_type = self.cipher_type.get()
        key = self.key_entry.get()

        try:
            if cipher_type == 'caesar':
                shift = int(key)
                encrypted = caesar_cipher_encrypt(text, shift)
            elif cipher_type == 'vigenere':
                encrypted = vigenere_cipher_encrypt(text, key)
            elif cipher_type == 'aes':
                key = key.encode()  # Ensure key is bytes
                encrypted = aes_encrypt(text, key)
            else:
                raise ValueError("Unsupported cipher type")

            self.encrypted_message.config(state='normal')
            self.encrypted_message.delete(1.0, tk.END)
            self.encrypted_message.insert(tk.END, encrypted)
            self.encrypted_message.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_message(self):
        text = self.decrypt_text.get()
        cipher_type = self.cipher_type_decrypt.get()
        key = self.key_entry_decrypt.get()

        try:
            if cipher_type == 'caesar':
                shift = int(key)
                decrypted = caesar_cipher_decrypt(text, shift)
            elif cipher_type == 'vigenere':
                decrypted = vigenere_cipher_decrypt(text, key)
            elif cipher_type == 'aes':
                key = key.encode()  # Ensure key is bytes
                decrypted = aes_decrypt(text, key)
            else:
                raise ValueError("Unsupported cipher type")

            self.decrypted_message.config(state='normal')
            self.decrypted_message.delete(1.0, tk.END)
            self.decrypted_message.insert(tk.END, decrypted)
            self.decrypted_message.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    app = EncryptionTool()
    app.mainloop()
