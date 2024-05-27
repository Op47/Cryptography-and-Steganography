from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key_data = key_file.read()
        private_key = serialization.load_pem_private_key(private_key_data, password=None)
    return private_key

def decrypt_message(encrypted_message, private_key):
    plaintext = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    private_key_path = "keys/private_key.pem"
    encrypted_message_path = "messages/extracted_encrypted_message.bin"

    private_key = load_private_key(private_key_path)

    with open(encrypted_message_path, "rb") as file:
        encrypted_message = file.read()

    decrypted_message = decrypt_message(encrypted_message, private_key)
    print("Decrypted message:", decrypted_message)
