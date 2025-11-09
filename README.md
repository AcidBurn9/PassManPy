# PassManPy

## Features

- CLI and Web* interfaces
- Multi-user support
- X25519 encryption
  - Private key for decryption is NOT saved anywhere and is derived from master password, which has to be re-entered upon every decryption attempt.
  - Public key for encryption allows adding passwords without re-entering master password.
- SQLite storage
- Optimal for local or self-hosted use

\* - Web interface is WIP.

## Warning

**NB! PassManPy does not enforce minimum password strength requirements.**

If an attacker gains access to the vault file, accounts with weak master passwords can be easily brute-forced. Use a weak master password at your own risk.

## Usage

### 1. Create a virtual environment

**`python3 -m venv venv-passman`**

### 2. Activate the virtual environment

Linux/macOS: **`source venv-passman/bin/activate`**

Windows: **`.\venv-passman\Scripts\Activate.ps1`**

### 3. Upgrade pip inside the venv

**`pip install --upgrade pip`**

### 4. Install dependencies from requirements.txt

**`pip install -r requirements.txt`**

### 5. Run PassManPy

**`python ./PassManCLI.py`**

### 6. Deactivate the virtual environment

**`deactivate`**
