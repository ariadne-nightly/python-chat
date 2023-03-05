import socket
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = 'localhost'  # Change this to the IP address of the first computer
PORT = 5000

# Generate a random secret key for AES encryption
SECRET_KEY = b'your_secret_key_here'

# Define the authentication function
def authenticate(message, hmac):
    # Compute the HMAC of the message using the secret key
    hmac_digest = hashlib.sha256(SECRET_KEY + message.encode('utf-8')).hexdigest()
    # Compare the HMACs to check for message integrity
    return hmac_digest == hmac

# Define the encryption function
def encrypt(message):
    # Generate a random initialization vector for AES encryption
    iv = b'your_iv_here'
    # Create an AES cipher object with the secret key and initialization vector
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    # Pad the message to a multiple of 16 bytes
    padded_message = pad(message.encode('utf-8'), 16)
    # Encrypt the padded message using the cipher object
    encrypted_message = cipher.encrypt(padded_message)
    # Combine the encrypted message and initialization vector into a JSON object
    return json.dumps({'message': encrypted_message.hex(), 'iv': iv.hex()})

# Define the decryption function
def decrypt(message):
    # Parse the JSON object to extract the encrypted message and initialization vector
    message_json = json.loads(message)
    encrypted_message = bytes.fromhex(message_json['message'])
    iv = bytes.fromhex(message_json['iv'])
    # Create an AES cipher object with the secret key and initialization vector
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    # Decrypt the encrypted message using the cipher object
    padded_message = cipher.decrypt(encrypted_message)
    # Remove the padding from the decrypted message
    return unpad(padded_message, 16).decode('utf-8')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}...")

    while True:
        # Get a message from the user
        message = input("Type your message: ")

        # Encrypt the message and send it to the server
        encrypted_message = encrypt(message)
        hmac_message = hashlib.sha256(SECRET_KEY + message.encode('utf-8')).hexdigest()
        s.sendall(encrypted_message.encode('utf-8'))
        s.sendall(hmac_message.encode('utf-8'))

        # Receive the encrypted response and HMAC from the server
        encrypted_response = s.recv(1024)
        hmac_response = s.recv(64).decode('utf-8')

        # Decrypt the encrypted response
        response = decrypt(encrypted_response.decode('utf-8'))

        # Authenticate the response using the HMAC
        if not authenticate(response, hmac_response):
            print("Response authentication failed!")
            continue

        # Print the response
        print(f"Received response: {response}")
