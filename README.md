# python-chat

This is a simple Python program for two computers to text each other securely (and only each other) over a network. The program uses the following security features:

- Two-factor authentication using TOTP (Time-Based One-Time Password)
- Encryption of messages using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode
- Message authentication using HMAC (Hash-Based Message Authentication Code) with SHA-256 (Secure Hash Algorithm 256)

## Requirements

- Python 3
- `pycryptodome` module (for AES encryption)
- `pyotp` module (for TOTP two-factor authentication)

## Usage

1. Start the server by running `python server.py` on the computer that you want to use as the server. This will listen for incoming connections on port 1234.
2. Start the client by running `python client.py` on the computer that you want to use as the client. This will prompt you to enter the IP address of the server and the TOTP authentication code.
3. Once the client is connected to the server, you can enter messages to send to the other computer. The messages will be encrypted and authenticated before being sent over the network.
4. To exit the program, simply type `exit` or press `Ctrl+C`.

## Limitations

- The program is currently set up to only allow communication between two computers (one server and one client).
- The program does not provide any anonymity, as the IP addresses of both computers are visible to each other.
- The program does not provide forward secrecy, as the same key and initialization vector are used for each session.

## License

This program is licensed under the MIT License. See the `LICENSE` file for more information.
