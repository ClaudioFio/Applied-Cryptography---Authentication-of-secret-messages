# Applied Cryptography - Authentication of secret messages

In this project, two programs, one Server and one Client, were developed for authenticated message exchange.
In particular, the Server can send authenticated and secret messages to the Client, which can verify the certificates, thus the authenticity of the message and decrypt them.

SimpleAuthority has been used as a Certification Authority (CA) for generating and managing digital keys and certificates, used by the Server and Client to provide them with cryptographic digital identities.

## Project specifications:

The Server:
- The server has a private key and a certificate;<br>
- Takes from keyboard a message to encrypt (the message length must be multiple of 16 bytes);<br>
- Encrypts the message with (unpadded) AES 128 CBC with a key hardcoded in the script;<br>
- Loads the private keys;<br>
- Signs the ciphertext (and the IV) with such a private key;<br>
- Saves the signature, the IV, and the ciphertext on a “message.<br>

The Client:
- Loads the server’s and the CA’s certificates;<br>
- TaVerifies the validity of the server certificate (only signature);<br>
- Loads the signature, the IV, and the ciphertext from the “message file”;<br>
- Verifies the signature with the public key embedded in the certificate;<br>
- Decrypts the message;<br>
- Prints the message on screen;<br>
