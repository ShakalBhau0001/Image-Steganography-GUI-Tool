import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image
import secrets
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Key derivation and Fernet wrapper


def derive_fernet_key_from_password(
    password: str, salt: bytes, iterations: int = 390000
) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


# LSB Steganography functions


def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def bits_needed_for_bytes(num_bytes: int) -> int:
    return num_bytes * 8


def embed_payload_in_image(
    input_image_path: str, payload: bytes, output_image_path: str
):
    img = Image.open(input_image_path)
    # Ensure in RGBA to preserve alpha if present
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    else:
        img = img.convert("RGBA")

    width, height = img.size
    num_pixels = width * height
    total_channels = num_pixels * 3  # we'll use R,G,B channels for embedding

    bits_needed = bits_needed_for_bytes(len(payload))
    if bits_needed > total_channels:
        raise ValueError(
            f"Payload too large to embed. Need {bits_needed} bits but image supports {total_channels} bits."
        )

    pixels = list(img.getdata())  # each pixel is (R,G,B,A)
    bit_iter = bytes_to_bits(payload)

    new_pixels = []
    channel_idx = 0  # we've used so far among R,G,B channels across all pixels

    for pix in pixels:
        r, g, b, a = pix
        components = [r, g, b]
        for c in range(3):
            try:
                bit = next(bit_iter)
                components[c] = (components[c] & ~1) | bit  # set LSB to bit
                channel_idx += 1
            except StopIteration:
                # no more bits to embed
                pass
        new_pixels.append((components[0], components[1], components[2], a))

    # If the leftover pixels not consumed by the loop above, they're already added into new_pixels
    steg_img = Image.new("RGBA", img.size)
    steg_img.putdata(new_pixels)
    # Save as PNG to avoid lossy compression
    steg_img.save(output_image_path, format="PNG")


def extract_payload_from_image(
    stego_image_path: str, payload_length_bytes: int
) -> bytes:
    img = Image.open(stego_image_path).convert("RGBA")
    pixels = list(img.getdata())
    bits = []
    for pix in pixels:
        r, g, b, a = pix
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    # first payload_length
    required_bits = payload_length_bytes * 8
    if required_bits > len(bits):
        raise ValueError(
            "Image does not contain enough embedded bits to extract requested payload."
        )

    out_bytes = bytearray()
    for i in range(0, required_bits, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out_bytes.append(byte)
    return bytes(out_bytes)


# Payload format and helpers

MAGIC = b"STEG"


def make_payload(encrypted_bytes: bytes, salt: bytes) -> bytes:
    return MAGIC + salt + struct.pack(">I", len(encrypted_bytes)) + encrypted_bytes


def parse_payload(raw: bytes):
    if len(raw) < 4 + 16 + 4:
        raise ValueError("Payload too small or corrupted.")
    if raw[:4] != MAGIC:
        raise ValueError(
            "MAGIC header not found. This image likely doesn't contain our payload."
        )
    salt = raw[4:20]
    enc_len = struct.unpack(">I", raw[20:24])[0]
    if len(raw) < 24 + enc_len:
        raise ValueError("Payload length mismatch / corrupted payload.")
    encrypted_bytes = raw[24 : 24 + enc_len]
    return salt, encrypted_bytes


# High-level functions: encrypt+embed and extract+decrypt


def encrypt_message_and_embed(
    image_path: str, message_bytes: bytes, password: str, output_image_path: str
):
    # Generate salt for KDF
    salt = secrets.token_bytes(16)
    key = derive_fernet_key_from_password(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message_bytes)  # bytes
    payload = make_payload(encrypted, salt)
    embed_payload_in_image(image_path, payload, output_image_path)


def extract_and_decrypt(stego_image_path: str, password: str):
    # Step 1: extraction of first 24 bytes for parse header
    header_bytes = extract_payload_from_image(stego_image_path, 24)
    if header_bytes[:4] != MAGIC:
        raise ValueError("No valid payload found in image (MAGIC mismatch).")
    salt = header_bytes[4:20]
    enc_len = struct.unpack(">I", header_bytes[20:24])[0]

    # extraction of the whole payload
    full_payload = extract_payload_from_image(stego_image_path, 24 + enc_len)
    salt2, encrypted_bytes = parse_payload(full_payload)
    if salt != salt2:
        raise ValueError("Internal consistency check failed (salt mismatch).")

    # Deriving key from password and salt as well as decrypt
    key = derive_fernet_key_from_password(password, salt)
    f = Fernet(key)
    try:
        decrypted = f.decrypt(encrypted_bytes)
    except Exception as e:
        raise ValueError(
            "Decryption failed. Wrong password or corrupted payload."
        ) from e

    return decrypted  # bytes


# Tkinter GUI


class ImageStegApp:
    def __init__(self, root):
        self.root = root
        root.title("Image Steganography - Encrypt & Embed in PNG Images")
        root.resizable(False, False)
        self.frame_top = tk.Frame(root, padx=10, pady=10)
        self.frame_top.pack(fill="both", expand=True)

        # Encrypt section
        enc_label = tk.Label(
            self.frame_top,
            text="1) Encrypt & Embed Message into Image",
            font=("Segoe UI", 11, "bold"),
        )
        enc_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))

        # Input image
        tk.Label(self.frame_top, text="Select carrier image (PNG recommended):").grid(
            row=1, column=0, sticky="w"
        )
        self.enc_image_path_var = tk.StringVar()
        tk.Entry(self.frame_top, textvariable=self.enc_image_path_var, width=48).grid(
            row=1, column=1, sticky="w"
        )
        tk.Button(self.frame_top, text="Browse", command=self.browse_enc_image).grid(
            row=1, column=2, padx=5
        )

        # Message text or file
        tk.Label(self.frame_top, text="Type message to hide:").grid(
            row=2, column=0, sticky="nw", pady=(8, 0)
        )
        self.msg_text = scrolledtext.ScrolledText(self.frame_top, width=40, height=6)
        self.msg_text.grid(row=2, column=1, sticky="w", pady=(8, 0))

        tk.Button(
            self.frame_top, text="Or load .txt file", command=self.load_txt_file
        ).grid(row=2, column=2, sticky="n", padx=5, pady=(8, 0))

        # Password entry
        tk.Label(self.frame_top, text="Encryption password (remember this):").grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )
        self.enc_password_var = tk.StringVar()
        tk.Entry(
            self.frame_top, textvariable=self.enc_password_var, show="*", width=30
        ).grid(row=3, column=1, sticky="w", pady=(8, 0))

        # Output filename
        tk.Label(self.frame_top, text="Output stego-image filename:").grid(
            row=4, column=0, sticky="w", pady=(8, 0)
        )
        self.output_name_var = tk.StringVar(value="stego_output.png")
        tk.Entry(self.frame_top, textvariable=self.output_name_var, width=30).grid(
            row=4, column=1, sticky="w", pady=(8, 0)
        )

        tk.Button(
            self.frame_top,
            text="Encrypt & Embed",
            command=self.handle_encrypt,
            bg="#2e7d32",
            fg="white",
        ).grid(row=4, column=2, padx=5, pady=(8, 0))

        # Separator
        tk.Label(self.frame_top, text="").grid(row=5, column=0, pady=6)

        # Decrypt section
        dec_label = tk.Label(
            self.frame_top,
            text="2) Extract & Decrypt Message from Image",
            font=("Segoe UI", 11, "bold"),
        )
        dec_label.grid(row=6, column=0, columnspan=3, sticky="w", pady=(0, 6))

        tk.Label(self.frame_top, text="Select stego-image (PNG):").grid(
            row=7, column=0, sticky="w"
        )
        self.dec_image_path_var = tk.StringVar()
        tk.Entry(self.frame_top, textvariable=self.dec_image_path_var, width=48).grid(
            row=7, column=1, sticky="w"
        )
        tk.Button(self.frame_top, text="Browse", command=self.browse_dec_image).grid(
            row=7, column=2, padx=5
        )

        tk.Label(self.frame_top, text="Decryption password:").grid(
            row=8, column=0, sticky="w", pady=(8, 0)
        )
        self.dec_password_var = tk.StringVar()
        tk.Entry(
            self.frame_top, textvariable=self.dec_password_var, show="*", width=30
        ).grid(row=8, column=1, sticky="w", pady=(8, 0))

        tk.Button(
            self.frame_top,
            text="Extract & Decrypt",
            command=self.handle_decrypt,
            bg="#1565c0",
            fg="white",
        ).grid(row=9, column=1, sticky="w", pady=(8, 0))

        # Decrypted message display
        tk.Label(self.frame_top, text="Decrypted message:").grid(
            row=10, column=0, sticky="nw", pady=(8, 0)
        )
        self.dec_msg_display = scrolledtext.ScrolledText(
            self.frame_top, width=60, height=8
        )
        self.dec_msg_display.grid(row=10, column=1, columnspan=2, pady=(8, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(
            root, textvariable=self.status_var, bd=1, relief="sunken", anchor="w"
        )
        self.status_label.pack(fill="x", side="bottom")

    # GUI helper functions
    def set_status(self, text: str):
        self.status_var.set(text)
        self.root.update_idletasks()

    def browse_enc_image(self):
        path = filedialog.askopenfilename(
            title="Select carrier image",
            filetypes=[
                ("PNG images", "*.png"),
                ("JPEG images", "*.jpg;*.jpeg"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.enc_image_path_var.set(path)

    def browse_dec_image(self):
        path = filedialog.askopenfilename(
            title="Select stego image",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            self.dec_image_path_var.set(path)

    def load_txt_file(self):
        path = filedialog.askopenfilename(
            title="Select text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.msg_text.delete("1.0", tk.END)
            self.msg_text.insert(tk.END, content)
            self.set_status(f"Loaded message from {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read text file: {e}")
            self.set_status("Failed to load text file")

    #  Handlers
    def handle_encrypt(self):
        img_path = self.enc_image_path_var.get().strip()
        password = self.enc_password_var.get()
        out_name = self.output_name_var.get().strip()
        msg = self.msg_text.get("1.0", tk.END).rstrip("\n")

        if not img_path:
            messagebox.showwarning("Missing input", "Please select a carrier image.")
            return
        if not os.path.exists(img_path):
            messagebox.showerror("File not found", "Carrier image path does not exist.")
            return
        if not password:
            messagebox.showwarning(
                "Missing password",
                "Please enter an encryption password (remember it!).",
            )
            return
        if not msg:
            messagebox.showwarning(
                "Missing message", "Please type a message or load a .txt file to embed."
            )
            return
        if not out_name:
            messagebox.showwarning(
                "Missing output filename",
                "Please enter an output filename for the stego image.",
            )
            return

        # Ensure output has .png extension for preserving lossless output
        if not out_name.lower().endswith(".png"):
            out_name += ".png"
        out_path = os.path.abspath(out_name)

        try:
            # Prepare message bytes
            message_bytes = msg.encode("utf-8")

            # encrypt + embed
            self.set_status("Encrypting and embedding... (this may take a moment)")
            encrypt_message_and_embed(img_path, message_bytes, password, out_path)
            self.set_status(f"Encryption & embedding complete. Saved: {out_path}")
            messagebox.showinfo(
                "Success", f"Message embedded successfully into:\n{out_path}"
            )
        except ValueError as ve:
            messagebox.showerror("Capacity/Error", f"{ve}")
            self.set_status("Error during embedding.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")
            self.set_status("Unexpected error.")

    def handle_decrypt(self):
        img_path = self.dec_image_path_var.get().strip()
        password = self.dec_password_var.get()

        if not img_path:
            messagebox.showwarning(
                "Missing input", "Please select a stego image to extract from."
            )
            return
        if not os.path.exists(img_path):
            messagebox.showerror(
                "File not found", "Selected stego image does not exist."
            )
            return
        if not password:
            messagebox.showwarning(
                "Missing password", "Please enter the decryption password."
            )
            return

        try:
            self.set_status("Extracting and decrypting... (this may take a moment)")
            decrypted_bytes = extract_and_decrypt(img_path, password)
            try:
                decoded = decrypted_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # Binary data or wrong encoding
                decoded = repr(decrypted_bytes)

            self.dec_msg_display.delete("1.0", tk.END)
            self.dec_msg_display.insert(tk.END, decoded)
            self.set_status("Extraction & decryption successful.")
            messagebox.showinfo(
                "Success",
                "Message successfully extracted and decrypted. See the box below.",
            )
        except ValueError as ve:
            messagebox.showerror("Decryption Error", f"{ve}")
            self.set_status("Decryption failed.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")
            self.set_status("Unexpected error.")


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = ImageStegApp(root)
    root.mainloop()
  
