import tkinter as tk
from tkinter import messagebox
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def decrypt_password(encrypted_data, master_password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_password = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_password) + unpadder.finalize()

def load_passwords():
    global passwords
    password_list.delete(0, tk.END)
    
    master_password = master_password_entry.get()

    if not master_password:
        messagebox.showwarning("Error", "Please enter your master password!")
        return

    if not os.path.exists("encrypted_passwords.txt"):
        messagebox.showwarning("Error", "No saved passwords found!")
        return

    with open("encrypted_passwords.txt", "rb") as file:
        lines = file.readlines()

    passwords = {}
    for i, line in enumerate(lines):
        try:
            parts = line.split(b": ", 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid line format (Line {i + 1}): {line}")

            label = parts[0].decode()
            encrypted_data = parts[1].strip()

            decrypted_password = decrypt_password(encrypted_data, master_password).decode()

            passwords[label] = decrypted_password
            password_list.insert(tk.END, label)
        except Exception as e:
            messagebox.showerror("Error", f"Error in line {i + 1}: {e}")
            return

def copy_password():
    selected = password_list.curselection()
    if not selected:
        messagebox.showwarning("Error", "Please select an entry!")
        return

    label = password_list.get(selected[0])
    password = passwords.get(label)
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", f"Password for '{label}' has been copied to the clipboard!")

def delete_password():
    selected = password_list.curselection()
    if not selected:
        messagebox.showwarning("Error", "Please select an entry!")
        return

    label = password_list.get(selected[0])
    if label in passwords:
        passwords.pop(label)
        save_passwords()
        load_passwords()
        messagebox.showinfo("Deleted", f"Password for '{label}' has been deleted!")

def save_passwords():
    master_password = master_password_entry.get()

    if not master_password:
        messagebox.showwarning("Error", "Please enter your master password!")
        return

    with open("encrypted_passwords.txt", "wb") as file:
        for label, password in passwords.items():
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

            file.write(f"{label}: ".encode() + salt + iv + encrypted_password + b'\n')

root = tk.Tk()
root.title("Password Manager")

tk.Label(root, text="Master Password:").pack(pady=5)
master_password_entry = tk.Entry(root, show="*", width=40)
master_password_entry.pack(pady=10)

tk.Label(root, text="Saved Passwords:").pack(pady=5)

password_list = tk.Listbox(root, width=50, height=15)
password_list.pack(pady=10)

tk.Button(root, text="Load Passwords", command=load_passwords).pack(pady=5)
tk.Button(root, text="Copy Password", command=copy_password).pack(pady=5)
tk.Button(root, text="Delete Password", command=delete_password).pack(pady=5)

root.mainloop()
