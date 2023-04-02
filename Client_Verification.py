# -*- coding: utf-8 -*-
"""
@author: Fiorenza Claudio
"""

import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Cipher block size, expressed in bytes.
block = algorithms.AES.block_size//8

# Read the CA's certificate.
ca_cert_file = input("Type the PEM file containing the CA's certification: ")
with open(ca_cert_file, 'rb') as f:
    ca_cert_text = f.read()
    
ca_cert = x509.load_pem_x509_certificate(ca_cert_text, backend=default_backend())

# Read CA's name and publick key
ca_name = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
ca_pubkey = ca_cert.public_key()

# Read the Server's certificate.
server_cert_file = input("Type the PEM file containing the Server's certification: ")
with open(server_cert_file, 'rb') as f:
    server_cert_text = f.read()
    
server_cert = x509.load_pem_x509_certificate(server_cert_text, backend=default_backend())

# Check the Server's certificate validity.
server_cert_issuer_name = server_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
if server_cert_issuer_name != ca_name:
    print("ERROR - Unknown CA: ", server_cert_issuer_name)
    sys.exit(1)

# Check the signature of the certificate:
ca_pubkey.verify(
    server_cert.signature,
    server_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Print confirmation of the Server's certificate.
server_name = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
print('Certificate ok')
print('\tCertificate issuer:', ca_name )
print('\tSigner name:', server_name )

# Read the signature, the IV and the ciphertext from a file.
message_file = input("Type the message's file to decrypt: ")
with open(message_file, 'rb') as f:
    server_signature = f.read(hashes.SHA256.digest_size*8) #256 bit
    iv = f.read(block)
    ciphertext = f.read()
    
# Read the Server's public key.
server_pubkey = server_cert.public_key()

ciphertext_iv = iv + ciphertext

# Verify the signature.
server_pubkey.verify(
    server_signature,
    ciphertext_iv,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Print the confirmation of the validity of the signature.
print ('Signature ok')

# Hardcoded key in the script
key = b'a1656c98456b9874d894a498152c4984'

# Decrypt the ciphertext.
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
ctx = cipher.decryptor()
plaintext = ctx.update(ciphertext) + ctx.finalize()

# Print the decrypted text  
print() 
print(str(plaintext, 'utf-8'))