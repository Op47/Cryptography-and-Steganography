from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_public_key(public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key_data = key_file.read()
        public_key = serialization.load_pem_public_key(public_key_data)
    return public_key

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

if __name__ == "__main__":
    public_key_path = "keys/public_key.pem"
    message = "This is a secret message."

    public_key = load_public_key(public_key_path)
    ciphertext = encrypt_message(message, public_key)

    with open("messages/encrypted_message.bin", "wb") as file:
        file.write(ciphertext)
