from Encryptions import encrypt_AES, decrypt_AES, generate_rsa_keys
from Encryptions import decrypt_AES_master, decrypt_AES_keys, decrypt_message_gcm, encrypt_message_gcm
from Accounts import AdminAccount, EmployeeAccount, ClientAccount, log_transaction, log_message, share_session_key

import json
import random
import bcrypt
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.x509 import Name, NameOID, CertificateBuilder
from cryptography.x509 import random_serial_number
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

# global variables to store the current user's information
current_public_key = None
client_random = None
server_random = None
current_session_key = None
current_iv = None
current_username = None

def create_self_signed_certificate(public_key_pem, private_key_pem):
    """Creates a self-signed X.509 certificate from PEM keys."""
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode()

    # Load the private key (already in PEM format)
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()


    # Load the public key (already in PEM format)
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Define certificate attributes
    subject = issuer = Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Coventry"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Warwick"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bank of Warwick"),
        x509.NameAttribute(NameOID.COMMON_NAME, "bankofwarwick.com"),
    ])

    # Create self-signed certificate
    certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1-year validity
        .sign(private_key, hashes.SHA256())  
    )

    # Return the certificate in PEM format
    return certificate.public_bytes(serialization.Encoding.PEM)

def save_keys_to_file(private_pem, public_pem, public_key_path="server_public_SERVER_SIDE.pem", private_key_path="server_private_SERVER_SIDE.pem"):
    """Encodes and saves the public/private keys to separate files."""
    
    # Encrypt private key using AES master key
    aes_master_key = decrypt_AES_master()  
    encrypted_private_pem = encrypt_AES(private_pem, aes_master_key)  # Encrypt the private key
    
    # Save the encrypted private key to file
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(encrypted_private_pem) 

    # Save the public key directly 
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_pem)  
    
    print(f"#Server# Keys saved to {private_key_path} and {public_key_path}")

def create_server_key_pair():
    # Generate RSA public/private keys
    private_key_b64, public_key_b64 = generate_rsa_keys()
    
    # Decode the base64-encoded keys to PEM format before saving them
    private_key_pem = base64.b64decode(private_key_b64)
    public_key_pem = base64.b64decode(public_key_b64)
    
    # Save them to files
    save_keys_to_file(private_key_pem, public_key_pem)
    
    return public_key_pem, private_key_pem

def retrieve_server_public(public_key_path="server_public_SERVER_SIDE.pem"):
 
    # Read the public key 
    with open(public_key_path, "rb") as pub_file:
        public_key = pub_file.read()
    
    # Return public key as PEM format
    return public_key.decode()

def retrieve_server_public_private(private_key_path="server_private_SERVER_SIDE.pem", 
                                   public_key_path="server_public_SERVER_SIDE.pem"):
    # decrypt AES master key
    aes_master_key = decrypt_AES_master()
    
    # Read the encrypted private key
    with open(private_key_path, "rb") as priv_file:
        encrypted_private_key = priv_file.read()
    
    decrypted_private_key = decrypt_AES_keys(encrypted_private_key, aes_master_key)

    # Read the public key
    with open(public_key_path, "rb") as pub_file:
        public_key = pub_file.read()
    
    # Return both private and public keys as PEM format
    return decrypted_private_key.decode(), public_key.decode()

# called by client, simulating being sent over a socket
def send_public_key_with_random(public_key, client_random1):
    """Client sends its public key with the client random
        Server returns its digital signature and server random
    """
    global client_random
    client_random = client_random1

    # creating server random
    global server_random
    server_random = os.urandom(16)

    server_private_key, server_public_key = retrieve_server_public_private()

    # Create and return the self-signed certificate
    digital_certificate = create_self_signed_certificate(server_public_key, server_private_key)
   
   # return digital certificate and server random
    return {
        "digital_certificate" : digital_certificate,
        "server_random" : server_random
    }

def derive_session_key_with_hkdf(shared_secret, client_random, server_random, iv_length=12):
    """
    Derives an AES key using HKDF, including an IV.
    The final AES key and IV are both derived from the shared secret and combined salts.
    """
    # Combine the client and server randoms to create a salt
    combined_salt = client_random + server_random  # Ensure server_random is in bytes

    # Create the HKDF instance
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Using SHA-256 as the hash function
        length=32 + iv_length,  # length for AES key (32 bytes) + IV (12 bytes)
        salt=combined_salt,  # Combined salt derived from client and server randoms
        info=None,  # No specific context
        backend=default_backend()
    )

    # Derive the session key & IV
    derived_data = hkdf.derive(shared_secret)  # shared_secret = keying material
    
    # Split the derived data into AES key and IV
    session_key = derived_data[:32]  # AES key (32 bytes)
    iv = derived_data[32:32+iv_length]  # IV (12 bytes)

    return session_key, iv

def decrypt_with_server_private_key(encrypted_data):
    private_key, public_key = retrieve_server_public_private() 

    # Retrieve the server's private key (assuming it's in bytes)
    private_key_pem = private_key.encode()  # Ensure this is in bytes

    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None  # Provide a password if the key is encrypted
    )

    # decrypt the provided data using private_key
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data

def store_session_key_json(decrypted_username, session_key, iv):
    """Encrypts and stores the session key + IV in a JSON file"""
    global current_username
   
   # directory used to store all session keys
    os.makedirs("session_keys_SERVER_SIDE_DEL", exist_ok=True)  
    key_iv_path = "session_keys_SERVER_SIDE_DEL/session_keys.json"

    aes_master_key = decrypt_AES_master()  # Retrieve AES master key

    # Encrypt session key and IV separately
    encrypted_session_key = encrypt_AES(session_key, aes_master_key)
    encrypted_iv = encrypt_AES(iv, aes_master_key)
    encrypted_username = encrypt_AES(decrypted_username, aes_master_key)

    # Convert to base64 for JSON storage
    enc_session_key_b64 = base64.b64encode(encrypted_session_key).decode('utf-8')
    enc_iv_b64 = base64.b64encode(encrypted_iv).decode('utf-8')
    enc_username_b64 = base64.b64encode(encrypted_username).decode('utf-8')

    # Prepare data to be stored
    data = {
        "username": enc_username_b64,
        "session_key": enc_session_key_b64,
        "iv": enc_iv_b64
    }

    # Write to JSON file (append mode)
    if os.path.exists(key_iv_path):
        with open(key_iv_path, 'r+') as file:
            # Load existing data
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                existing_data = []

            # Append new data
            existing_data.append(data)

            # Move back to the beginning of the file and overwrite
            file.seek(0)
            json.dump(existing_data, file, indent=4)
            file.truncate()  # Remove any leftover data

    else:
        with open(key_iv_path, 'w') as file:
            json.dump([data], file, indent=4)

    return True

# called from client side, used to share the shared secret
def send_shared_key(shared_data, signed_encrypted_data):
    
    # decrypt shared_secret using private key
    decrypted_shared_data = decrypt_with_server_private_key(shared_data)

    global current_public_key
    global current_username
    global current_iv
    global current_session_key

    current_public_key = serialization.load_pem_public_key(
        current_public_key
    )

    # Verify the signature using user public key
    try:
        current_public_key.verify(
            signed_encrypted_data,
            shared_data,  
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("#Server# Signature is valid.")
    except InvalidSignature:
        print("#Server# Signature is invalid.")
        return False

    print("#Server# Successfully decrypted shared secret using private key.")

    # split into username and shared secret key
    username_length = decrypted_shared_data[0]
    decrypted_username = decrypted_shared_data[1:1 + username_length].decode('utf-8')
    decrypted_shared_secret = decrypted_shared_data[1 + username_length:]
    print(f"#Server# Derived username: {decrypted_username}")

    # derive the aes key
    session_key, iv = derive_session_key_with_hkdf(decrypted_shared_secret, client_random, server_random)
    print(f"#Server# Derived AES Key: {session_key.hex()}")
    print(f"#Server# Generated IV: {iv.hex()}")

    current_session_key = session_key
    current_iv = iv

    # store the aes session key
    if (store_session_key_json(decrypted_username=decrypted_username, session_key=session_key, iv=iv)):
        print("#Server# successfully stored session key in JSON file.")
    return True    

def load_session_key_json(current_username):
    """Retrieves and decrypts the session key + IV from JSON file"""
    print(f"#Server# Loading the session key of {current_username}")

    global current_session_key
    global current_iv

    key_iv_path = "session_keys_SERVER_SIDE_DEL/session_keys.json"

    aes_master_key = decrypt_AES_master()  # Retrieve AES master key

    try:
        with open(key_iv_path, 'r') as file:
            data_list = json.load(file)

            for data in data_list:
                enc_username_b64 = data["username"]
                enc_session_key_b64 = data["session_key"]
                enc_iv_b64 = data["iv"]

                # Decode the base64 encoded values
                decoded_username = base64.b64decode(enc_username_b64)
                decrypt_username = decrypt_AES(decoded_username, aes_master_key)

                if decrypt_username == current_username:  # Match username
                    print("#server# inside the matched")
                    
                    # Decode from base64
                    encrypted_session_key = base64.b64decode(enc_session_key_b64)
                    encrypted_iv = base64.b64decode(enc_iv_b64)

                    # Decrypt session key and IV
                    session_key = decrypt_AES(encrypted_session_key, aes_master_key)
                    iv = decrypt_AES(encrypted_iv, aes_master_key)

                    current_session_key = session_key
                    current_iv = iv
                    return session_key, iv  # Return decrypted values

        print(f"Error: No session key found for user '{current_username}'.")
        return None, None  # User not found

    except FileNotFoundError:
        print("Error: session_keys.json file not found.")
        return None, None
    except json.JSONDecodeError:
        print("Error: JSON decode error.")
        return None, None

# called from client side, includes the encrypted login credentials using the session key
def login(encrypted_login_credentials):
    # Load accounts data 
    accounts_data = load_accounts()
   
    global current_session_key
    global current_username

    # retrieve private key to decrypt
    decrypted_credentials = decrypt_with_server_private_key(encrypted_data=encrypted_login_credentials)
  
    # Split the decrypted data into username and password
    username, password = decrypted_credentials.decode().split(':')
    print(f"#Server# decrypted username: {username}")
    print(f"#Server# decrypted password: {password}")

    # Verify credentials against stored account data
    account = verify_credentials(username, password, accounts_data)

    if account: # if user exists
        otp = send_otp(account) # send an otp
        current_username = username
        session_key, iv = load_session_key_json(current_username=current_username) # load session key
        share_session_key(session_key=session_key, iv=iv) #share session key with Accounts.py 
        return otp, account
    else:
        print("#Server# Invalid username or password.")
        return None, None

def register(account, filename="accounts_SERVER_SIDE_DEL.json"):
    """Encrypt account details and add them to the existing accounts file without removing old users."""
   
    # Decrypt account details using server private key
    for key in account:
        if key != "public_key":  # Skip decryption for public_key
            if key != "role": # Skip decryption for role
                encrypted_value = base64.b64decode(account[key])  # Decode Base64 string back to bytes
                decrypted_value = decrypt_with_server_private_key(encrypted_value)
            else: 
                decrypted_value = base64.b64decode(account[key])
            if decrypted_value is not None:
                account[key] = decrypted_value.decode('utf-8')  # Convert decrypted bytes back to string
            else:
                print(f"#Server# Failed to decrypt {key}")
                return False


    accounts = load_accounts(filename)  # Load existing users

    # Encrypt sensitive details before saving
    enc_username = encrypt_AES(account["username"])
    print("#Server# Encrypting:", account["username"])
    print("#Server# Encrypted:", enc_username)

    enc_password = encrypt_AES(hash_password(account["password"]))  # Hash before encryption
    enc_email = encrypt_AES(account["email"])
    enc_role = account["role"].lower()
    enc_status = encrypt_AES(account["status"])
    enc_public_key = encrypt_AES(account["public_key"])
    global current_public_key
    current_public_key = account["public_key"] # set public key

    # Convert bytes to Base64 strings for JSON serialization
    enc_username = base64.b64encode(enc_username).decode('utf-8')
    enc_password = base64.b64encode(enc_password).decode('utf-8')
    enc_email = base64.b64encode(enc_email).decode('utf-8')
    enc_status = base64.b64encode(enc_status).decode('utf-8')
    enc_public_key = base64.b64encode(enc_public_key).decode('utf-8')

    # Create account object
    if enc_role == "admin":
        new_account = AdminAccount(enc_username, enc_password, enc_email, enc_status, enc_public_key)
        accounts["admin"].append(new_account.__dict__)
    elif enc_role == "employee":
        new_account = EmployeeAccount(enc_username, enc_password, enc_email, enc_status, enc_public_key)
        accounts["employee"].append(new_account.__dict__)
    elif enc_role == "user":
        new_account = ClientAccount(enc_username, enc_password, enc_email, enc_status, enc_public_key)
        enc_accountNumber = encrypt_AES(new_account.account_number)

        # Encrypt the account balance; convert the integer 0 to a string, then encode to bytes
        enc_balance = encrypt_AES(str(0).encode('utf-8'))
        new_account.account_number = base64.b64encode(enc_accountNumber).decode('utf-8')
        new_account.account_balance = base64.b64encode(enc_balance).decode('utf-8')

        # append the accounts objbect
        accounts["user"].append(new_account.__dict__)
    else:
        print("#Server# Invalid account role.")
        return False

    # Save updated accounts back to JSON
    with open(filename, "w") as f:
        json.dump(accounts, f, indent=4)

    print(f"#Server# Account for {account['username']} added successfully!")
    return True

# Helper function: Generate OTP
def generate_otp():
    return ''.join(random.choices('0123456789', k=6)) # random 6 numbers

# Helper function: Load accounts from JSON file, or create an empty structure if file doesn't exist.
def load_accounts(filename="accounts_SERVER_SIDE_DEL.json"):
    """Load existing accounts from JSON file, or create an empty structure if file doesn't exist."""
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {"admin": [], "employee": [], "user": []}  # Reset if corrupt file
    return {"admin": [], "employee": [], "user": []}

# Helper function: Hash a password with bcrypt
def hash_password(password):
    """Hash a password with bcrypt and a generated salt."""
    salt = bcrypt.gensalt()  # Generate a salt
    hashed = bcrypt.hashpw(password.encode(), salt)  # Hash the password with the salt
    return hashed

# Helper function: Verify a password with bcrypt
def verify_password(password, hashed_password):
    """Verify a password against its bcrypt hash."""
    if not isinstance(password, bytes): # ensure password is in bytes
      password = password.encode()
    if not isinstance(hashed_password, bytes): # ensure hashed password is in bytes
      hashed_password = hashed_password.encode()
    return bcrypt.checkpw(password, hashed_password) # compare the two passwords

def verify_credentials(username, password, accounts_data):
    """Verify username and password and return the account if valid."""
    for account_type in accounts_data:
        for account in accounts_data[account_type]:# loop over all accounts
            
            dec_username = decrypt_AES(base64.b64decode(account['username'])) # decrypt username
            dec_password = decrypt_AES(base64.b64decode(account['password'])) # decrypt hashed password

            # if username and password match found
            if dec_username == username and verify_password(password, dec_password):
                return account  # Only return account, OTP will be handled elsewhere

    return None  # No matching account found

# Helper function: Simulate sending OTP (print to the console)
def send_otp(account):
    otp = generate_otp()
    print(f"#Server# OTP sent to your email. OTP: {otp}")
    return otp

# client calls this function, over a simulated socket
def transfer_money(sender, receiver, amount):
    """Client sends encrypted transfer request using session key
        Server decrypts request using session key and logs transfer
    """
    # Check if sender has enough balance
    print("#Server# Checking sufficient sender balance...")
    # Deduct amount from sender's account
    print("#Server# Deducting amount from sender's account...")
    # Add amount to receiver's account
    print("#Server# Adding amount to receiver's account...")

    global current_username
    session_key, iv = load_session_key_json(current_username) # load session key

    if session_key is None or iv is None:
        print("#Server# Failed to retrieve AES key and IV. Transaction aborted.")
        return
    
    # decrypt using session key
    decrypted_sender_account = decrypt_message_gcm(sender, session_key)
    decrypted_receiver_account = decrypt_message_gcm(receiver, session_key)
    decrypted_ammount = decrypt_message_gcm(amount, session_key)

    # Log transaction
    log_transaction(decrypted_sender_account, decrypted_receiver_account, decrypted_ammount)
    print("#Server# Amount added to receiver's account")

    return True

# client calls this function, over simulated socket
def send_message(sender_username, receiver_username, message):
    """client sends encrypted message request using session key
    Server decrypts message using session key and logs it
    """
    global current_username
    session_key, iv = load_session_key_json(current_username) # load session key

    if session_key is None or iv is None:
        print("#Server# Failed to retrieve AES key and IV. Transaction aborted.")
        return

    # decrypt received request using session key
    decrypted_sender_username = decrypt_message_gcm(sender_username, session_key)
    print(f"#Server# Sending message from {decrypted_sender_username}...")
    decrypted_receiver_username = decrypt_message_gcm(receiver_username, session_key)
    print(f"#Server #Receiving message at {decrypted_receiver_username}'s account...")
    decrypted_message = decrypt_message_gcm(message, session_key)
    print(f"#Server# Message is {decrypted_message}")
      
    # Log message
    log_message(sender=decrypted_sender_username, receiver=decrypted_receiver_username, message=decrypted_message)
    return True

""" generating server private/public keys, call if server_private.pem or server_publc.pem were lost"""   
def main():
     # Assuming server's keys are generated and returned as PEM
    server_public_key, server_private_key = create_server_key_pair()  # Generate and save keys

if __name__ == "__main__":
    main()

 