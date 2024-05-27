from PIL import Image

def hide_message_in_image(image_path, output_path, message_path):
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

if __name__ == "__main__":
    hide_message_in_image("images/input_image.png", "images/stego_image.png", "messages/encrypted_message.bin")
