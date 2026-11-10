# CipherKavach

CipherKavach is a local Flask web app and Python command-line tool for encrypting and decrypting files with a password. The Flask app listens only on `127.0.0.1` by default. It sends file bytes to the Python backend on your computer for processing; encryption does not happen only in the browser.

> **About the original CLI:** no Python source files were present in the supplied project folder when this app was built. This project therefore includes a new CLI that shares the same crypto module as the web app. Its `.ckv` files are compatible with this project's CLI and web app. Compatibility with files made by a missing earlier CLI cannot be confirmed.

## Project structure

```text
CipherKavach/
├── app.py                  Flask routes, upload checks, and downloads
├── cipherkavach.py         Python command-line interface
├── cipherkavach_crypto.py  Shared AES-GCM file format and crypto functions
├── requirements.txt        Python dependencies
├── templates/
│   └── index.html          Page structure
└── static/
    ├── app.js              Tabs, file picker, upload, and download behavior
    └── style.css           Responsive interface styles
```

The browser submits the selected file and password to `/api/encrypt` or `/api/decrypt`. Flask checks the inputs and size, then calls `encrypt_bytes` or `decrypt_bytes` from `cipherkavach_crypto.py`, the same functions the CLI imports. Each request uses its own temporary directory for the upload; the directory is removed before the download response is sent. The generated result is streamed from memory and is not saved as a server-side file.

## Encryption format and password recovery

New `.ckv` files use AES-256-GCM with a fresh random 16-byte salt and 12-byte nonce per file. PBKDF2-HMAC-SHA256 with 600,000 iterations derives the encryption key from the password. The versioned header is authenticated along with the ciphertext. GCM detects wrong passwords and changes to authenticated file data, but it cannot distinguish a wrong password from corruption; the app shows one general decryption error for both. Files using an unsupported format or version are rejected.

CipherKavach does not save passwords and cannot recover them. Keep the password safe and retain the original file until you have checked the encrypted download. The application does not store file history, use a database, or upload to cloud storage. Do not expose the local development server to a public network.

The upload limit defaults to 50 MB per file and is enforced in the browser and on the server. To change it, set `CIPHERKAVACH_MAX_FILE_SIZE` to a byte count before starting the app; the browser limit uses the same configured value rendered by Flask.

## Run on Windows with VS Code

Open this project folder in VS Code. In the integrated PowerShell terminal, run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If PowerShell blocks environment activation, use Command Prompt in VS Code instead:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Keep the terminal running, then open **http://127.0.0.1:5000** in your browser. Press `Ctrl+C` in the terminal to stop the server. The app does not deploy itself or listen on other devices.

## Use the CLI

The CLI prompts for passwords without displaying them:

```powershell
python cipherkavach.py encrypt .\document.pdf
python cipherkavach.py decrypt .\document.pdf.ckv
```

By default, encryption writes `<input>.ckv`. Decryption removes a trailing `.ckv` from the output name; for another name, provide `-o`:

```powershell
python cipherkavach.py decrypt .\document.ckv -o .\recovered.pdf
```

## Local checks

Run the built-in application checks from the activated environment:

```powershell
python -m unittest discover -s tests -v
```

