from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # AES-256
with open("secret.key", "wb") as f:
    f.write(key)

print("AES-256 Secret Key Generated Successfully")
