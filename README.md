# SecurePass

This is a simple password management application built using Python's `tkinter` and `cryptography` libraries. It allows users to securely store passwords using encryption with a master password. The application also provides functionality to load, copy, and delete encrypted passwords.

## Features

- **Input Custom Passwords**: You can manually input the password you want to store.
- **Encrypt Passwords**: Securely encrypt passwords using PBKDF2-HMAC with AES encryption.
- **Save Encrypted Passwords**: Store encrypted passwords along with a label (name or description) for easy identification.
- **Load Stored Passwords**: Load previously stored encrypted passwords after entering the correct master password.
- **Copy Passwords**: Copy decrypted passwords to the clipboard for use.
- **Delete Passwords**: Delete specific stored passwords from the list.

## Installation

To get started with this application, you need to install Python and the required dependencies:

1. **Install Python 3.x**:
   - Download and install Python from [python.org](https://www.python.org/).
   
2. **Install the required libraries**:
   - Use a package manager like `pip` to install the necessary libraries:
     - `tkinter` (for the GUI)
     - `cryptography` (for encryption functionalities)
   
   You can install the required libraries by running:
   ´´bash
   pip install cryptography
   ´´bash
   
   `tkinter` comes bundled with Python, so no additional installation is needed for it.

4. **Run the application**:
   - Once the dependencies are installed, simply run the Python script to start the application.

## Usage

### Storing Passwords

1. Enter a **label** (e.g., "Google Account") in the provided input field. This helps identify the password later.
2. Enter the password you wish to store in the second input field.
3. Enter your **master password**, which will be used to encrypt the password.
4. Click **Encrypt and Save Password** to securely encrypt and store the password in a file.

### Loading and Managing Stored Passwords

1. Enter your **master password**.
2. Click **Load Passwords** to load stored encrypted passwords.
3. Select a password from the list and click **Copy Password** to copy the decrypted password to your clipboard.
4. To delete a password, select it from the list and click **Delete Password**.

## Encryption Details

Passwords are encrypted using the AES algorithm in CBC mode. The key is derived from the master password using PBKDF2-HMAC with a random salt. The encrypted password, along with the salt and initialization vector (IV), is stored securely.

## File Format

Encrypted passwords are stored in the file `encrypted_passwords.txt`. Each entry consists of a label followed by the encrypted data, including the salt, IV, and ciphertext.

## Security Considerations

- Always keep your master password secure and private.
- The application uses AES encryption with a 256-bit key and PBKDF2 for key derivation, which provides a high level of security for password storage.

## License

This project is open-source and available under the GNU License.
