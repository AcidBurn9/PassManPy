# PassManPy

## About

PassManPy is a "light" Password Manager written in Python, which supports both CLI and Web interfaces. Multiple users are supported. PassMan encrypts passwords using public key cryptography (X25519) and stores them in an SQLite database. Intended for use in local or self-hosted environment.

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

### 5. Run PassMan

**`python ./PassManCLI.py`**

### 6. Deactivate the virtual environment

**`deactivate`**
