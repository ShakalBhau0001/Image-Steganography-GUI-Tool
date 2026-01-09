# 🖼️ Image-Steganography-GUI-Tool 🔐

A Python-based **Image Steganography** that allows you to **encrypt a secret message** and embed it inside a **PNG image**, and later **extract + decrypt** it using the correct password.

This project uses **Fernet symmetric encryption**, **PBKDF2-HMAC key derivation**, and **LSB (Least Significant Bit) image steganography**, all wrapped inside a clean **Tkinter GUI**.

---

## 🧱 Project Structure

```bash
Image-Steganography-GUI-Tool/
│
├── image_steganography.py     # Main GUI application
└── README.md                  # Project documentation
```

---

## ✨ Features

## 🔐 Encryption & Embedding

- Encrypts message using **Fernet (AES-128 with authentication)**
- Password-based key derivation using **PBKDF2-HMAC (SHA256, 390k iterations)**
- Embeds encrypted payload into **PNG image pixels**
- Uses **LSB steganography** on RGB channels
- Preserves image quality (lossless PNG output)

## 🔓 Extraction & Decryption

- Extracts embedded data from image LSBs
- Validates payload using **MAGIC header**
- Regenerates encryption key using stored salt
- Securely decrypts hidden message
- Displays recovered message inside GUI

## 🖥 GUI Highlights

- Simple and clean **Tkinter interface**
- Browse carrier image **(PNG recommended)**
- Type message or load message from `.txt` file
- Password-protected encryption
- Automatic output image generation
- Status bar & proper error handling

---

## 🛠 Technologies Used

| Technology                             | Role                        |
| -------------------------------------- | --------------------------- |
| **Python 3**                           | Core language               |
| **Tkinter**                            | GUI framework               |
| **Pillow (PIL)**                       | Image processing            |
| **cryptography (Fernet + PBKDF2HMAC)** | Encryption & key derivation |
| **struct / base64**                    | Binary data handling        |
| **LSB Steganography**                  | Data hiding in images       |

---

## 📌 Requirements

Make sure you install required dependencies:

```bash
pip install cryptography pillow
```

Standard libraries like `secrets`, `tkinter`, `base64`, and `struct` are already included with Python.

---

## ▶️ How to Run

**1. Clone the repository:**

```bash
git clone https://github.com/ShakalBhau0001/Image-Steganography-GUI-Tool.git
```

**2. Enter the project folder:**

```bash
cd Image-Steganography-GUI-Tool
```

**3. Run the GUI:**

```bash
python image_steganography.py
```

---

## 📁 Supported File Format

- **Input (Carrier Image):** PNG (recommended), JPG/JPEG
- **Output (Stego Image):** PNG only
- **Message Input:** Text or `.txt` file

> ⚠️ Output is always saved as PNG to avoid lossy compression that can destroy hidden data.

---

## ⚙️ How It Works

**1️⃣ Key Derivation**

- Password → PBKDF2-HMAC(SHA256, 390k iterations) → 32-byte key → Fernet key

**2️⃣ Encryption**

- Message → `Fernet.encrypt()`
- Encrypted payload is packed with:
    - 4-byte magic header (`STEG`)
    - 16-byte random salt
    - 4-byte encrypted data length
    - Encrypted message bytes

**3️⃣ Embedding (LSB)**

- Payload bits embedded into **LSB of RGB channels**
- Each pixel stores up to **3 bits**
- Alpha channel is preserved

**4️⃣ Extraction**

- Reads LSBs from image pixels
- Reconstructs payload
- Validates MAGIC header
- Regenerates Fernet key using password + salt
- Decrypts message securely

---

## 🌟 Future Enhancements

- Binary file hiding
- Image capacity calculator
- Progress bar during embedding
- Drag & drop support
- CLI version for automation

---

## 🪪 Author

> **Creator: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
