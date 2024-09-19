# Simple Encryption Tool

## Overview

The Simple Encryption Tool is a graphical application built with Python's Tkinter library. It provides functionalities for encrypting and decrypting messages using various ciphers, including Caesar Cipher, Vigenère Cipher, and AES Encryption. This tool is designed for educational purposes and demonstrates basic encryption techniques.

## Features

- **Caesar Cipher**: Shift-based encryption method.
- **Vigenère Cipher**: Polygraphic substitution cipher using a keyword.
- **AES Encryption**: Symmetric encryption method using the Fernet module from the `cryptography` library.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/vrushali10/simple-encryption-tool.git
   ```

2. **Navigate to the Project Directory**

   ```bash
   cd simple-encryption-tool
   ```

3. **Create and Activate a Virtual Environment (Optional but recommended)**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use .venv\Scripts\activate
   ```

4. **Install Required Packages**

   ```bash
   pip install -r requirements.txt
   ```

   Ensure `requirements.txt` includes:
   ```
   cryptography
   ```

## Usage

1. **Run the Application**

   ```bash
   python SET.py
   ```

2. **Encrypt a Message**

   - Navigate to the **Encrypt** tab.
   - Enter the text you want to encrypt in the "Enter Text:" field.
   - Select the cipher type from the dropdown menu.
   - Enter the key or shift value as required by the chosen cipher.
   - Click the **Encrypt** button.
   - The encrypted message will be displayed in the "Encrypted Message:" area.

3. **Decrypt a Message**

   - Navigate to the **Decrypt** tab.
   - Enter the encrypted text in the "Enter Encrypted Text:" field.
   - Select the cipher type from the dropdown menu.
   - Enter the key or shift value used during encryption.
   - Click the **Decrypt** button.
   - The decrypted message will be displayed in the "Decrypted Message:" area.

## Example

### Caesar Cipher

- **Encryption**
  - Input Text: `hello`
  - Shift: `3`
  - Encrypted Output: `khoor`

- **Decryption**
  - Encrypted Text: `khoor`
  - Shift: `3`
  - Decrypted Output: `hello`

### Vigenère Cipher

- **Encryption**
  - Input Text: `hello`
  - Key: `KEY`
  - Encrypted Output: `RIJVS`

- **Decryption**
  - Encrypted Text: `RIJVS`
  - Key: `KEY`
  - Decrypted Output: `HELLO`

### AES Encryption

- **Encryption**
  - Input Text: `hello`
  - Key: `your-32-byte-key-here` (Base64 encoded)
  - Encrypted Output: `gAAAAABe...` (Base64 encoded)

- **Decryption**
  - Encrypted Text: `gAAAAABe...`
  - Key: `your-32-byte-key-here` (Base64 encoded)
  - Decrypted Output: `hello`

## Notes

- Ensure that the key used for AES encryption/decryption is a valid 32-byte Base64 encoded string.
- For educational purposes, this tool demonstrates basic encryption methods and should not be used for securing sensitive information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.