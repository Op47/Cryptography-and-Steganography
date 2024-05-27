from secure import Secure
import os

secure = Secure()

def main():
    while True:
        inp = int(input("""
1. Secure File into Image
2. Secure File into Video
3. Decrypt File from Image
4. Decrypt File from Video
5. Generate RSA Keys
6. Exit
Choice: """))

        if inp == 1:
            fName = input('File to be secured: ')
            coverImg = input("Cover image location [images/input_image.png]: ")
            if coverImg != "":
                if os.path.isfile(coverImg):
                    secure.secure_file(fName, coverImg)
                else:
                    print(f"Cover Image [{coverImg}] does not exist...")
                    secure.secure_file(fName)
            else:
                secure.secure_file(fName)
        elif inp == 2:
            fName = input('File to be secured: ')
            coverVideo = input("Cover video location [videos/input_video.mp4]: ")
            if coverVideo != "":
                if os.path.isfile(coverVideo):
                    secure.secure_file_video(fName, coverVideo)
                else:
                    print(f"Cover Video [{coverVideo}] does not exist...")
                    secure.secure_file_video(fName)
            else:
                secure.secure_file_video(fName)
        elif inp == 3:
            stegoImg = input("Stego image: ")
            fName = input('Output file name [output/decrypted.txt]: ')
            if fName == "":
                secure.desecure_file(stegoImg)
            else:
                secure.desecure_file(stegoImg, fName)
        elif inp == 4:
            stegoVideo = input("Stego video: ")
            fName = input('Output file name [output/decrypted.txt]: ')
            if fName == "":
                secure.desecure_file_video(stegoVideo)
            else:
                secure.desecure_file_video(stegoVideo, fName)
        elif inp == 5:
            secure.generate_key()
        elif inp == 6:
            exit()
        else:
            print("Invalid Input...")

if __name__ == "__main__":
    main()
