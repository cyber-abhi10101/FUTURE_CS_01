from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

def encrypt_file(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(enc_data, key):
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    data = file.read()
    key = load_key()
    encrypted = encrypt_file(data, key)

    with open(os.path.join(ENCRYPTED_FOLDER, file.filename), "wb") as f:
        f.write(encrypted)

    return "✅ File Encrypted & Uploaded Successfully"

@app.route("/download/<filename>")
def download(filename):
    key = load_key()

    with open(os.path.join(ENCRYPTED_FOLDER, filename), "rb") as f:
        enc_data = f.read()

    decrypted = decrypt_file(enc_data, key)
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    with open(filepath, "wb") as f:
        f.write(decrypted)

    return send_file(filepath, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
