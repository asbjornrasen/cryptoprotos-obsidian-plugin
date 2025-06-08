CryptoProtos Plugin

This plugin allows you to encrypt and decrypt entire Markdown files in your vault using a password.
It uses AES-256-GCM encryption with a unique salt and IV for each operation.
The plugin prompts for a password every time — it is never stored.
Features

    🔐 Encrypt the current TXT file with a password

    🔓 Decrypt the current TXT file with a password

    ✏️ Fully integrates with editor

    🔄 Compatible with external tools (e.g., Python, JavaScript) if the encryption format is respected

    🚫 No password storage — total client-side security

    ## 🚀 How to Use

    1. Open the file you want to encrypt or decrypt.
    2. Open the Command Palette (`Ctrl+P` / `Cmd+P`).
    3. Run:
       - `CryptoProtos: Encrypt current file...`
       - or `CryptoProtos: Decrypt current file...`
    4. Enter your password. The file is replaced with encrypted or decrypted content.

Security Note:

The password is never stored or cached. If you forget it, the file content cannot be decrypted.
Always use strong, memorable passwords and store them securely.

www.cryptoprotos.tech
