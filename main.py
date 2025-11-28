from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import time

# ------------------------- AES -------------------------
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(ciphertext, key):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ------------------------- RSA -------------------------
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

def rsa_encrypt(plaintext, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt(ciphertext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    ct = base64.b64decode(ciphertext)
    return cipher.decrypt(ct).decode()

# ------------------------- MAIN -------------------------
if __name__ == "__main__":
    print("=== PROGRAM AES & RSA ===")
    text = input("Masukkan teks rahasia: ")

    print("\n=== HASIL AES ===")
    aes_key = get_random_bytes(16)

    start = time.time()
    aes_cipher = aes_encrypt(text, aes_key)
    end = time.time()
    aes_time = (end - start) * 1000  # ms

    print("Ciphertext:", aes_cipher)
    print("Dekripsi  :", aes_decrypt(aes_cipher, aes_key))
    print(f"Waktu Enkripsi AES : {aes_time:.4f} ms")
    print(f"Ukuran Ciphertext AES : {len(aes_cipher)} karakter")

    print("\n=== HASIL RSA ===")
    priv, pub = generate_rsa_keys()

    start = time.time()
    rsa_cipher = rsa_encrypt(text, pub)
    end = time.time()
    rsa_time = (end - start) * 1000  # ms

    print("Ciphertext:", rsa_cipher)
    print("Dekripsi  :", rsa_decrypt(rsa_cipher, priv))
    print(f"Waktu Enkripsi RSA : {rsa_time:.4f} ms")
    print(f"Ukuran Ciphertext RSA : {len(rsa_cipher)} karakter")

    print("\n=== PERBANDINGAN ===")
    speed_ratio = rsa_time / aes_time if aes_time > 0 else 0
    size_ratio = len(rsa_cipher) / len(aes_cipher)

    print(f"AES lebih cepat {speed_ratio:.2f}x dibanding RSA")
    print(f"Ciphertext RSA {size_ratio:.2f}x lebih besar dari AES")
