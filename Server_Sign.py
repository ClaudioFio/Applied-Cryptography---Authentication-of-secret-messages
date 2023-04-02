# -*- coding: utf-8 -*-
"""
@author: Fiorenza Claudio
"""

import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Cipher block size, expressed in bytes.
block = algorithms.AES.block_size//8

# Read the message to encrypt.
input_message = input('Type the message to encrypt: ')
message = str.encode(input_message)

# Check if the message lenght is multiple of the block size.
if len(message) % block != 0:
    sys.exit('The file must be multiple of ' + str(block) + ' bytes.')
    
# Hardcoded key in the script
key = b'a1656c98456b9874d894a498152c4984'

# Encrypt the message with a random IV.
iv = os.urandom(block)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
ctx = cipher.encryptor()
ciphertext = ctx.update(message) + ctx.finalize()

ciphertext_iv = iv + ciphertext

# Load the private key.
server_key_file = input("Type the PEM file containing the Server's private key: ")
with open(server_key_file, 'rb') as f:
    server_prvkey_text = f.read()

server_prvkey = serialization.load_pem_private_key(server_prvkey_text , None, default_backend())

# Sign the ciphertext (and the IV)
signature = server_prvkey.sign(
    ciphertext_iv,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Write signature, the IV, and the ciphertext
with open('messagefile.txt', 'wb') as f:
    f.write(signature)
    f.write(iv)
    f.write(ciphertext)
    
# Print confirmation message
print()
print("Message encrypted!")