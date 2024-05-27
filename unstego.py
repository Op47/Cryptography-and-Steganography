from PIL import Image

def extract_message_from_image(image_path, message_length):
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

if __name__ == "__main__":
    stego_image_path = "images/stego_image.png"
    with open("messages/encrypted_message.bin", "rb") as file:
        message_length = len(file.read())

    extracted_message = extract_message_from_image(stego_image_path, message_length)
    with open("messages/extracted_encrypted_message.bin", "wb") as file:
        file.write(extracted_message)
