import cv2 #opencv-python
import types
import numpy as np
import subprocess
from cryptography.fernet import Fernet

def encrypt_message(msg,key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(str.encode(msg))
    return cipher_text

def decrypt_message(cipher_text,key):
    cipher_suite = Fernet(str.encode(key))
    plain_text = cipher_suite.decrypt(str.encode(cipher_text))
    return plain_text

def messageToBinary(message):

    if type(message) == str:
        return ''.join([ format(ord(i), "08b") for i in message ])
    elif type(message) == bytes or type(message) == np.ndarray:
        return [ format(i, "08b") for i in message ]
    elif type(message) == int or type(message) == np.uint8:
        return format(message, "08b")
    else:
        raise TypeError("Input type not supported")

def hideData(image, secret_message):
    # calculate the maximum bytes to encode
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    print("Maximum bytes to encode:", n_bytes)

    #Let's make sure that we have enough image size to encode data
    if len(secret_message) > n_bytes:
        raise ValueError("Error - insufficient bytes, need bigger image or less data !!")
  
    secret_message = secret_message.decode() + "#####" # using this string as the delimiter
    
    data_index = 0
    binary_secret_msg = messageToBinary(secret_message)

    data_len = len(binary_secret_msg)
    for values in image:
        for pixel in values:
            # convert RGB values to binary format
            r, g, b = messageToBinary(pixel)
            # modify the LSB only if there is still data to store
            if data_index < data_len:
                # red pixel
                pixel[0] = int(r[:-1] + binary_secret_msg[data_index], 2)
                data_index += 1
            if data_index < data_len:
                # green pixel
                pixel[1] = int(g[:-1] + binary_secret_msg[data_index], 2)
                data_index += 1
            if data_index < data_len:
                # blue pixel
                pixel[2] = int(b[:-1] + binary_secret_msg[data_index], 2)
                data_index += 1
            # break out of the loop if the data is over
            if data_index >= data_len:
                break

    return image

def showData(image):

    binary_data = ""
    for values in image:
        for pixel in values:
            r, g, b = messageToBinary(pixel) #convert the red,green and blue values into binary format
            binary_data += r[-1] #red pixel
            binary_data += g[-1] #green pixel
            binary_data += b[-1] #blue pixel
    # split by 8-bits
    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
    # convert from bits to characters
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-5:] == "#####": #check if we have reached the delimiter which is "#####"
            break
    #print(decoded_data)
    return decoded_data[:-5] #remove the delimiter to show the original hidden message

def encode_text(): 
    image = cv2.imread("base_image.png") # Read the input image using OpenCV-Python.
    
    #details of the image
    print("The shape of the image is: ",image.shape) #check the shape of image to calculate the number of bytes in it
      
    data = input("Enter data to be encoded : ") 
    if (len(data) == 0): 
        raise ValueError('Data is empty')
    
    key = Fernet.generate_key()
    print("\n Secret Key ==> " + key.decode())
    print("\n Keep the above mentioned key as secret, since the key is required to decrypt the data.")
    enc_data = encrypt_message(data, key)

    filename = "encoded_image.png"
    encoded_image = hideData(image, enc_data) # call the hideData function to hide the secret message into the selected image
    cv2.imwrite(filename, encoded_image)
    print("\n Process completed, encoded image name 'encoded_image.png'")

def decode_text():
    # read the image that contains the hidden image
    image_name = input("Enter the name of the steganographed image that you want to decode (with extension) :") 
    image = cv2.imread(image_name) #read the image using cv2.imread() 

    text = showData(image)

    key = input("\n Enter the key to decrypt message : ")
    de_text = decrypt_message(text,key)

    return de_text

banner = """

 _____                               _____ _                               
|_   _|                             / ____| |                              
  | |  _ __ ___   __ _  __ _  ___  | (___ | |_ ___  __ _  __ _ _ __   ___  
  | | | '_ ` _ \ / _` |/ _` |/ _ \  \___ \| __/ _ \/ _` |/ _` | '_ \ / _ \ 
 _| |_| | | | | | (_| | (_| |  __/  ____) | ||  __/ (_| | (_| | | | | (_) |
|_____|_| |_| |_|\__,_|\__, |\___| |_____/ \__\___|\__, |\__,_|_| |_|\___/ 
                        __/ |                       __/ |                  
                       |___/                       |___/              

- Team Gooseberry Security (https://gooseberrysec.com)

"""
def Steganography(): 
    
    subprocess.call('clear')
    print(banner)

    a = input("\n 1. Encode the data (we will use a default image to encode data)\n 2. Decode the data \n Your input is: ")
    userinput = int(a)
    if (userinput == 1):
        print("\nEncoding....")
        encode_text() 
          
    elif (userinput == 2):
        print("\nDecoding....") 
        print("Decoded message is ==> " + decode_text().decode()) 
        print("")
    else: 
        raise Exception("Enter correct input")

if __name__ == '__main__' :

    # Calling main function
    Steganography()