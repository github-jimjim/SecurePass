import tkinter as tk
from tkinter import messagebox
import secrets
import string
import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def generate_random_key(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def encrypt_password(password, master_password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(master_password.encode())
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()

    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + encrypted_password

def save_encrypted_password():
    master_password = master_password_entry.get()
    password_to_encrypt = key_output.get(1.0, tk.END).strip()
    label = entry_label.get()

    if password_to_encrypt and label:
        encrypted_data = encrypt_password(password_to_encrypt, master_password)

        with open("encrypted_passwords.txt", "ab") as file:
            file.write(f"{label}: ".encode())  
            file.write(encrypted_data)
            file.write(b'\n')

        messagebox.showinfo("Saved", "The encrypted password has been saved!")
    else:
        messagebox.showwarning("Error", "No password or label entered!")

def show_security_level():
    security_level_var = security_scale.get()
    length = int(security_level_var) + 6
    random_key = generate_random_key(length)
    key_output.delete(1.0, tk.END)
    key_output.insert(tk.END, random_key)

def copy_to_clipboard():
    random_key = key_output.get(1.0, tk.END).strip()
    if random_key:
        root.clipboard_clear()
        root.clipboard_append(random_key)
        messagebox.showinfo("Copied", "The key has been copied to the clipboard!")

root = tk.Tk()
root.title("Security Check")

security_label = tk.Label(root, text="Security Level")
security_label.pack(pady=10)

security_scale = tk.Scale(root, from_=0, to=24, orient="horizontal")
security_scale.pack(pady=10)

check_button = tk.Button(root, text="Generate Password", command=show_security_level)
check_button.pack(pady=10)

entry_label = tk.Entry(root, width=40)
entry_label.pack(pady=10)
entry_label.insert(0, "Enter label here...")

key_output = tk.Text(root, height=2, width=40)
key_output.pack(pady=10)

copy_button = tk.Button(root, text="Copy Key", command=copy_to_clipboard)
copy_button.pack(pady=10)

master_password_label = tk.Label(root, text="Master Password")
master_password_label.pack(pady=5)

master_password_entry = tk.Entry(root, show="*", width=40)
master_password_entry.pack(pady=10)

save_encrypted_button = tk.Button(root, text="Save Encrypted Password", command=save_encrypted_password)
save_encrypted_button.pack(pady=10)

root.mainloop()
