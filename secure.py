import os
import cv2
from PIL import Image
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class Secure:
    def generate_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("keys/private_key.pem", "wb") as private_file:
            private_file.write(private_key_pem)

        with open("keys/public_key.pem", "wb") as public_file:
            public_file.write(public_key_pem)

    def secure_file(self, file_path, cover_image_path="images/input_image.png"):
        public_key = self._load_public_key("keys/public_key.pem")
        with open(file_path, "r") as file:
            message = file.read()
        encrypted_message = self._encrypt_message(message, public_key)
        with open("messages/encrypted_message.bin", "wb") as encrypted_file:
            encrypted_file.write(encrypted_message)
        self._hide_message_in_image(cover_image_path, "images/stego_image.png", "messages/encrypted_message.bin")

    def desecure_file(self, stego_image_path, output_file_path="output/decrypted.txt"):
        with open("messages/encrypted_message.bin", "rb") as file:
            message_length = len(file.read())
        extracted_message = self._extract_message_from_image(stego_image_path, message_length)
        with open("messages/extracted_encrypted_message.bin", "wb") as file:
            file.write(extracted_message)
        private_key = self._load_private_key("keys/private_key.pem")
        decrypted_message = self._decrypt_message(extracted_message, private_key)
        with open(output_file_path, "w") as output_file:
            output_file.write(decrypted_message)

    def secure_file_video(self, file_path, cover_video_path="videos/input_video.mp4"):
        public_key = self._load_public_key("keys/public_key.pem")
        with open(file_path, "r") as file:
            message = file.read()
        encrypted_message = self._encrypt_message(message, public_key)
        with open("messages/encrypted_message.bin", "wb") as encrypted_file:
            encrypted_file.write(encrypted_message)
        self._hide_message_in_video(cover_video_path, "videos/stego_video.mp4", "messages/encrypted_message.bin")

    def desecure_file_video(self, stego_video_path, output_file_path="output/decrypted.txt"):
        with open("messages/encrypted_message.bin", "rb") as file:
            message_length = len(file.read())
        extracted_message = self._extract_message_from_video(stego_video_path, message_length)
        with open("messages/extracted_encrypted_message.bin", "wb") as file:
            file.write(extracted_message)
        private_key = self._load_private_key("keys/private_key.pem")
        decrypted_message = self._decrypt_message(extracted_message, private_key)
        with open(output_file_path, "w") as output_file:
            output_file.write(decrypted_message)

    def _load_public_key(self, public_key_path):
        with open(public_key_path, "rb") as key_file:
            public_key_data = key_file.read()
            public_key = serialization.load_pem_public_key(public_key_data)
        return public_key

    def _load_private_key(self, private_key_path):
        with open(private_key_path, "rb") as key_file:
            private_key_data = key_file.read()
            private_key = serialization.load_pem_private_key(private_key_data, password=None)
        return private_key

    def _encrypt_message(self, message, public_key):
        ciphertext = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def _decrypt_message(self, encrypted_message, private_key):
        plaintext = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')

    def _hide_message_in_image(self, image_path, output_path, message_path):
        image = Image.open(image_path)
        encoded_image = image.copy()

        with open(message_path, "rb") as file:
            message = file.read()

        message_bits = ''.join([format(byte, '08b') for byte in message])
        message_len = len(message_bits)
        
        if message_len > image.size[0] * image.size[1] * 3:
            raise ValueError("Message is too large to hide in the image.")

        message_index = 0
        pixels = list(encoded_image.getdata())
        
        for i in range(len(pixels)):
            if message_index < message_len:
                pixel = list(pixels[i])
                for j in range(3):
                    if message_index < message_len:
                        pixel[j] = (pixel[j] & 0xFE) | int(message_bits[message_index])
                        message_index += 1
                pixels[i] = tuple(pixel)
            else:
                break

        encoded_image.putdata(pixels)
        encoded_image.save(output_path)

    def _extract_message_from_image(self, image_path, message_length):
        image = Image.open(image_path)

        pixels = list(image.getdata())
        message_bits = []

        for pixel in pixels:
            for channel in range(3):
                message_bits.append(pixel[channel] & 1)

        message_bytes = bytearray()
        for i in range(0, message_length * 8, 8):
            byte = 0
            for bit in message_bits[i:i+8]:
                byte = (byte << 1) | bit
            message_bytes.append(byte)
        
        return bytes(message_bytes)

    def _hide_message_in_video(self, video_path, output_path, message_path):
        cap = cv2.VideoCapture(video_path)
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_path, fourcc, cap.get(cv2.CAP_PROP_FPS), (int(cap.get(3)), int(cap.get(4))))

        with open(message_path, "rb") as file:
            message = file.read()

        message_bits = ''.join([format(byte, '08b') for byte in message])
        message_len = len(message_bits)
        message_index = 0

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            for row in frame:
                for pixel in row:
                    for channel in range(3):
                        if message_index < message_len:
                            pixel[channel] = (pixel[channel] & 0xFE) | int(message_bits[message_index])
                            message_index += 1

            out.write(frame)

        cap.release()
        out.release()

    def _extract_message_from_video(self, video_path, message_length):
        cap = cv2.VideoCapture(video_path)
        message_bits = []

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            for row in frame:
                for pixel in row:
                    for channel in range(3):
                        message_bits.append(pixel[channel] & 1)

            if len(message_bits) >= message_length * 8:
                break

        cap.release()

        message_bytes = bytearray()
        for i in range(0, message_length * 8, 8):
            byte = 0
            for bit in message_bits[i:i+8]:
                byte = (byte << 1) | bit
            message_bytes.append(byte)
        
        return bytes(message_bytes)
