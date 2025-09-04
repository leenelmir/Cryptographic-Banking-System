import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

master_key =  b'\x1c7\xe6\xaa\xcf\x14\x95\xb6C3\xfb|\x15\x8e\x8ej\xca:\x89\x17\xa4\xe0|$\x15\x88\xf0n\xd2N2U'
encrypt_master_key = b'C\xcf\x1bb\n\r_\xb3,0\xdc\xda][\xd8\xd2k\xef8\xdd;\xb3\x15@zB\xead\x9fp\xe3G'

def encrypt_message_gcm(message, session_key, iv):
    """
    Encrypts a message using AES-GCM with the derived AES key (32-byte) and IV (12-byte).
    """

    # create cipher
    cipher = AES.new(session_key, AES.MODE_GCM, iv)

    #encrypt message using cipher
    ciphertext, tag = cipher.encrypt_and_digest(message.encode()) 

    # Combine IV, Tag, and Ciphertext
    encrypted_data = iv + tag + ciphertext
    
    # Encode in base64 for safe transmission
    return base64.b64encode(encrypted_data).decode()

def decrypt_message_gcm(encrypted_msg, session_key):
    """
    Decrypts a message encrypted with AES-GCM.
    """
    encrypted_data = base64.b64decode(encrypted_msg)

    iv = encrypted_data[:12]  # Extract IV
    tag = encrypted_data[12:28]  # Extract authentication tag
    ciphertext = encrypted_data[28:]  # Extract ciphertext

    cipher = AES.new(session_key, AES.MODE_GCM, iv) # create cipher using session key
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag) # use cipher to decrypt the text

    return decrypted_message.decode()

def generate_master_key():
    # AES master key
    global key

    aes_master_key = get_random_bytes(32)  # 256-bit key
    key = aes_master_key
    print("AES Master Key:", aes_master_key)

    # Assume this encryption key is stored securely (on a HSM)
    encryption_key = get_random_bytes(32)  # 256-bit key
    print("AES Encryption Key:", encryption_key)

    # Encrypt the AES master key using AES GCM
    encrypted_master_key = encrypt_AES_master(aes_master_key, encryption_key)
    print("Encrypted AES Master Key:", encrypted_master_key)

    # Store the encrypted master key in a file called master_key_SERVER_SIDE
    with open("master_key_SERVER_SIDE", "wb") as key_file:
        key_file.write(encrypted_master_key)  

def encrypt_AES_master(data, key=encrypt_master_key):
    # Generate a random nonce (12 bytes recommended for GCM)
    nonce = get_random_bytes(12)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce)  # AES cipher in GCM mode
    if not isinstance(data, bytes):
        data = data.encode()
    
    ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt the data and get the authentication tag

    # Return nonce + tag + ciphertext in base64 format
    return base64.b64encode(nonce + tag + ciphertext)  

# AES ENCRYPTION
def encrypt_AES(data, key = master_key):
    # Generate a random nonce (12 bytes recommended for GCM)
    nonce = get_random_bytes(12)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce)  # AES cipher in GCM mode
    if not isinstance(data, bytes):
        data = data.encode()
    
    ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt data and get the authentication tag

    # Return nonce + tag + ciphertext in base64 format
    return base64.b64encode(nonce + tag + ciphertext)  

# AES DECRYPTION
def decrypt_AES(data, key=master_key):
   
    """Decrypts data using AES in GCM mode, extracts nonce, tag, and ciphertext."""

    # Decode the base64-encoded data
    decdata = base64.b64decode(data)

    # Extract nonce, tag, and ciphertext
    nonce = decdata[:12]  # nonce : 12 bytes
    tag = decdata[12:28]  # tag: 16 bytes
    ciphertext = decdata[28:]  # ciphertext

    # Initialize the cipher for decryption
    decipher = AES.new(key, AES.MODE_GCM, nonce)

    # Decrypt and verify the tag
    decrypted = decipher.decrypt_and_verify(ciphertext, tag)
    try:
            # Check if the decrypted data can be decoded to a string
            return decrypted.decode('utf-8')
    except UnicodeDecodeError:
            # If decoding fails, return raw bytes
            return decrypted

def decrypt_AES_keys(data, key=master_key):
    """Decrypts data using AES in GCM mode, extracts nonce, tag, and ciphertext."""
    # Decode the base64-encoded data
   
    decdata = base64.b64decode(data)
   
    # Extract nonce, tag, and ciphertext
    nonce = decdata[:12]  # nonce :12 bytes
    tag = decdata[12:28]  # tag: 16 bytes 
    ciphertext = decdata[28:]  # ciphertext

    # Initialize the cipher for decryption
    decipher = AES.new(key, AES.MODE_GCM, nonce)

    # Decrypt and verify the tag
    decrypted = decipher.decrypt_and_verify(ciphertext, tag)

    return decrypted  # Return the decrypted message as a string

def decrypt_AES_master(key=encrypt_master_key):
    """Decrypts AES master key using encrypt_master_key."""
    
    # Read the encrypted master key from the file
    with open('master_key_SERVER_SIDE', "rb") as key_file:
        encrypted_data = key_file.read()

   # print("Encrypted Master Key:", encrypted_data)
    
    # Decode the base64-encoded data
    decdata = base64.b64decode(encrypted_data)
  #  print("Decoded Encrypted Master Key:", decdata)
    
    # Extract nonce, tag, and ciphertext
    nonce = decdata[:12]  # nonce: 12 bytes
    tag = decdata[12:28]  # tag: 16 bytes
    ciphertext = decdata[28:]  # ciphertext

    # Initialize the cipher for decryption
    decipher = AES.new(key, AES.MODE_GCM, nonce)
    
    # Decrypt and verify the tag
    decrypted_data = decipher.decrypt_and_verify(ciphertext, tag)

    #print("Decrypted master key:")
    #print(decrypted_data)

    # Return the decrypted data as a string
    return decrypted_data  

# RSA KEY PAIR GENERATION
def generate_rsa_keys():
    """generates 2048-bit RSA public/private key pair"""

    private_key = rsa.generate_private_key(
        public_exponent=65537, # large prime
        key_size=2048           # 2048-bit rsa keys
    )
    public_key = private_key.public_key()

    # Serialize Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize Public Key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # return the pem files of the private/public keys
    return base64.b64encode(private_pem).decode(), base64.b64encode(public_pem).decode()

""" RUN THIS FUNCTION IF master_key_SERVER_SIDE was lost, 
set the master_key and encrypt_master_key accordingly """
def main():
   generate_master_key()

if __name__ == "__main__":
    main()
