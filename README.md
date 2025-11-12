# 🔒 File Encryptor Tool (AES-256-GCM)

A simple yet secure **File Encryption & Decryption Tool** built in Python.  
It uses **AES-256-GCM** for encryption and a **password-protected master key** for secure key management.

![Build Status](https://github.com/Lokeswar72/file-encryptor/actions/workflows/python-tests.yml/badge.svg)

---

## 🚀 Features
- AES-256-GCM file encryption & decryption
- Master key wrapped with password using scrypt (key derivation)
- Change password anytime without re-encrypting files
- Integrity and authenticity validation
- Interactive CLI password prompts
- Built-in unit tests (pytest)
- GitHub Actions CI for test automation

---

## 🧠 Tech Stack
| Component | Technology |
|------------|-------------|
| **Language** | Python 3.11+ |
| **Library** | [cryptography](https://cryptography.io/en/latest/) |
| **Testing** | PyTest |
| **Version Control** | Git & GitHub |
| **CI/CD** | GitHub Actions |

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository
```bash
git clone https://github.com/Lokeswar72/file-encryptor.git
cd file-encryptor
```

### 2️⃣ Create & activate a virtual environment
```bash
python -m venv .venv
# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1
```

### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

---

## 🪄 Usage

### Generate a master key
```bash
python encryptor.py generate-master-key
```
Creates a new AES master key and encrypts it with a password-derived key (scrypt).  
Stores the wrapped key at `keys/master_key.bin.enc`.

---

### Encrypt a file
```bash
python encryptor.py encrypt examples/secret.txt
```
Creates an encrypted file: `examples/secret.txt.enc`.

---

### Decrypt a file
```bash
python encryptor.py decrypt examples/secret.txt.enc
```
Decrypts the file back to `examples/secret.txt`.

---

### Change password
```bash
python encryptor.py change-password
```
Unwraps your master key using the old password and re-wraps it using a new one —  
so you can rotate passwords without re-encrypting all files.

---

## 🧪 Running Tests
```bash
pytest -q
```

If everything is working, you’ll see:
```
..                                                                   [100%]
2 passed in 0.50s
```

---

## 🧰 GitHub Actions CI
This repository includes a workflow that automatically:
- Sets up Python 3.9, 3.10, and 3.11
- Installs all dependencies
- Runs your PyTest suite

You can see the latest build status at the top of this README.

---

## ✅ Example Output
```
(.venv) PS> python encryptor.py generate-master-key
Enter password to protect the master key:
Confirm password:
Generated and wrapped master key -> keys\master_key.bin.enc
```

---

## 📁 Project Structure
```
file-encryptor/
│
├── encryptor.py                  # Main CLI program
├── tests/
│   └── test_encryptor.py         # Unit tests
├── requirements.txt              # Dependencies
├── .github/workflows/            # CI pipeline
│   └── python-tests.yml
├── keys/                         # Encrypted master key (gitignored)
└── README.md                     # Project documentation
```

---

## 🛡️ Security Notes
- Keep your `keys/master_key.bin.enc` backed up safely.
- Never commit or share your master key file or passwords.
- Use strong, unique passwords.
- Test decryption regularly to verify backups.

---

## 🧑‍💻 Author
**Lokeswar**  
GitHub: [@Lokeswar72](https://github.com/Lokeswar72)

---

## 📜 License
This project is open source and available under the [MIT License](LICENSE).
