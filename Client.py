from Server import login, register, send_public_key_with_random, send_shared_key
from Server import transfer_money, send_message, retrieve_server_public
from Encryptions import generate_rsa_keys, encrypt_AES, decrypt_AES, encrypt_message_gcm, decrypt_message_gcm
from Accounts import request_transactions, request_all_transactions, request_all_messages

import os
from cryptography.hazmat.primitives import serialization
import base64
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES

# global variables containing logged in user's info
current_salt = None
current_local_encryption_key = None
current_session_key = None
current_iv = None
current_username = None

# Send sign up request to server
def register_user(username, password, email, account_level, status):
    
    # Generate RSA public/private keys for user
    client_private_key, public_key = generate_rsa_keys()  
    public_pem = base64.b64decode(public_key)
    private_pem = base64.b64decode(client_private_key)

    # Generate client random salt
    client_random = os.urandom(16)

    # Send public key & client random to server
    response = send_public_key_with_random(public_pem, client_random)
    
    # Receive server's digital certificate & server random
    digital_certificate = response['digital_certificate']
    server_random = response['server_random']
                
    # Extract the server's public key
    server_public_key = extract_public_key_from_certificate(digital_certificate)

    # Check server public key extracted
    if server_public_key:
        print("#Client# Successfully extracted server public key")
    else :
        print("#Client# Server public key invalid.")    
    
    # create account
    status = "active"
    account = {"username": username, "password": password, "email": email, "role": account_level, "status": status, "public_key": public_pem}
    
    for key in account:
        if key != "public_key" :  # Skip encryption for public_key
            if key == "role" :    # Skip encryption for role
             account[key] = base64.b64encode(account[key].encode()).decode()
            else: 
             account[key] = base64.b64encode(encrypt_with_server_public_key(account[key].encode())).decode()


    # Create and save account on SERVER
    if (register(account)):
        print("#Client# Account created successfully.")

        # create random salt for client-side kdf 
        global current_salt
        current_salt = os.urandom(16)
        
        # store the salt for client-side kdf
        key_iv_path = f'session_keys_CLIENT_SIDE_DEL/{username}_salt'
        with open(key_iv_path, 'wb') as key_iv_file:
            key_iv_file.write(current_salt)

        print("#Client# wrote the salt to file")  

        # derive client-side kdf key
        encrypted_key = derive_key_using_kdf(password=password,salt=current_salt)

        # store client-side kdf key in global variable
        global current_local_encryption_key
        current_local_encryption_key = encrypted_key

        # save client's public/private keys encrypted using the kdf key
        save_client_public_private_keys(private_pem, public_pem, username, encrypted_key, current_salt)

        # Client continues TLS handshake 

        # Client generates a shared secret (random value) 
        shared_secret = os.urandom(32)  #  shared secret
        username_bytes = username.encode('utf-8')
        username_length = len(username_bytes)
        
        # Create a combined message: username length + username + shared secret
        combined_data = bytes([username_length]) + username_bytes + shared_secret

        # Derive AES session key and IV using shared secret and randoms as salt
        session_key, iv = derive_session_key_with_hkdf(shared_secret, client_random, server_random)
        print(f"#Client# Derived AES Key: {session_key.hex()}")
        print(f"#Client# Generated IV: {iv.hex()}")

        # Client encrypts shared secret using server's public key 
        encrypted_shared_secret = encrypt_with_server_public_key(combined_data)
        print("#Client# Encrypted shared secret")

        # Client signs the encrypted shared secret using its private key
        signed_encrypted_secret = sign_with_client_private_key(encrypted_shared_secret, private_pem)
        print("#Client# Signed encrypted shared secret")

        # Client shares the encrypted and signed secret with server
        if (send_shared_key(encrypted_shared_secret, signed_encrypted_secret)):  # if server could derive using kdf
            print("#Client# Successfully shared the AES key with server")
        
            key_path = f'session_keys_CLIENT_SIDE_DEL/{username}_key.enc'
            iv_path = f'session_keys_CLIENT_SIDE_DEL/{username}_iv.enc'

            # encrypt the session key and iv using the client-side kdf-key          
            encrypted_session_key = encrypt_AES(session_key, current_local_encryption_key)
            encrypted_iv = encrypt_AES(iv, current_local_encryption_key)

            # store the encrypted session key
            with open(key_path, 'wb') as key_file:
                key_file.write(encrypted_session_key)
            print("#Client# wrote the session key to file")    

            # store the encrypted iv
            with open(iv_path, 'wb') as iv_file:
                iv_file.write(encrypted_iv)
            print("#Client# wrote the iv to file")    

    else:
        print("#Client# Account creation failed.")    

def register_static_users():
    # Create a static admin, employee, and user account
    register_user(username="admin1", password="Admin!", email="admin@gmail.com", account_level="admin", status="active")         
    register_user(username="employee1", password="Employee!", email="emp@gmail.com", account_level="employee", status="active")
    register_user(username="user1", password="User!!", email="user@gmail.com", account_level="user", status="active")
    print("Created static users successfully: admin1, employee1, user1.")
    return

def extract_public_key_from_certificate(cert_pem):
    """
    Extracts the public key from a PEM-encoded X.509 certificate.
    
    :param cert_pem: The server's self-signed certificate in PEM format (bytes).
    :return: The extracted public key in PEM format (bytes).
    """
    try:
        # Load the certificate
        certificate = x509.load_pem_x509_certificate(cert_pem)

        # Extract the public key
        public_key = certificate.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key_pem  # Return the public key in PEM format

    except Exception as e:
        print(f"Error extracting public key: {e}")
        return None

def derive_key_using_kdf(password: str, salt: bytes):
    """Derives a 256-bit key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode()) # returns the 256-bit key

def save_client_public_private_keys(private_pem, public_pem, username, encryption_key, salt):
    """Encrypts and saves a client's public and private keys securely."""
    print(f"#Client# Saving public/private keys saved for {username}...")

    # Encrypt the private key using AES
    encrypted_private_key = encrypt_AES(private_pem, encryption_key)

    # Save the public key in `client_public_keys` folder
    public_key_path = f"client_public_keys_CLIENT_SIDE_DEL/{username}_public.pem"
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_pem)

    # Save encrypted private key with salt in `client_private_keys` folder
    private_key_path = f"client_private_keys_CLIENT_SIDE_DEL/{username}_private.enc"
    with open(private_key_path, "w") as priv_file:
        json.dump({
            "salt": base64.b64encode(salt).decode(),  # Convert salt to string for JSON
            "encrypted_key": base64.b64encode(encrypted_private_key).decode()
        }, priv_file, indent=4)

    print(f"#Client# Public/Private keys saved for {username}")
    
def derive_session_key_with_hkdf(shared_secret, client_random, server_random, iv_length=12):
    """
    Derives an AES key using HKDF, including an IV.
    The session key and IV are derived from the shared secret and combined salts.
    """
    # Combine the client and server randoms to create a salt
    combined_salt = client_random + server_random  

    # Create the HKDF instance
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # SHA-256 as the hash function
        length=32 + iv_length,  # length for AES key (32 bytes) + IV (12 bytes)
        salt=combined_salt,  # Combined salt derived from client and server randoms
        info=None,  # No specific context 
        backend=default_backend()
    )

    # Derive the key & IV
    derived_data = hkdf.derive(shared_secret)  # shared_secret is the input keying material
    
    # Split the derived data into AES key & IV
    session_key = derived_data[:32]  # AES key (32 bytes)
    iv = derived_data[32:32+iv_length]  # IV (12 bytes)

    # session key and iv are used for client-server communications
    return session_key, iv

def encrypt_with_server_public_key(data):

    # Retrieve the server's public key from a secure HTTPS endpoint (assuming server provides this option)
        server_public_key = retrieve_server_public()
        if isinstance(server_public_key, str):
            server_public_key = server_public_key.encode('utf-8')

        # Load the public key using serialization
        server_public_key = serialization.load_pem_public_key(server_public_key)

        # Encrypt the data with the server's public key
        try:
            encrypted_data = server_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
            print("#Client# Data encrypted successfully.")
        except Exception as e:
            print(f"#Client# An error occurred during encryption: {e}")

        return encrypted_data

def sign_with_client_private_key(data, private_key_pem):
    """Sign the AES session key with the client's private key."""

    # Load the private key using serialization (no password)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # sign the data with the private key
    signature = private_key.sign(
        data,
        padding.PKCS1v15(), # padding : PKCS#1 v1.5
        hashes.SHA256() # hash : SHA-256
    )
    
    return signature

def set_logged_in_username(username): # sets the global variable current_username to username
    global current_username
    current_username = username

def get_logged_in_username(): # returns the username of the currently logged in user
    global current_username
    return current_username    

def load_session_key(current_username, password):

    """Retrieve the AES session key and IV for the current user"""

    global current_local_encryption_key
    global current_session_key
    global current_iv
    
    # Load the salt from the file username_salt 
    salt_path = f'session_keys_CLIENT_SIDE_DEL/{current_username}_salt'  
    try:
        with open(salt_path, 'rb') as salt_file:
            salt = salt_file.read()
            print(f"#Client# Successfully loaded the salt for {current_username}")
    except FileNotFoundError:
        print(f"#Client# Error: Failed to find salt file for {current_username}")
        return None, None

    # Derive the KDF key using the password and salt
    current_local_encryption_key = derive_key_using_kdf(password, salt)
    print(f"#Client# Derived local encryption key")

    # Load the session key
    session_key_path = f'session_keys_CLIENT_SIDE_DEL/{current_username}_key.enc'
    try:
        with open(session_key_path, 'rb') as key_file:
            encrypted_session_key = key_file.read()  
            print(f"#Client# Successfully loaded the encrypted session key for {current_username}")
    except FileNotFoundError:
        print(f"#Client# Error: Failed to find session key file for {current_username}")
        return None, None

    # Load the IV
    iv_path = f'session_keys_CLIENT_SIDE_DEL/{current_username}_iv.enc'
    try:
        with open(iv_path, 'rb') as iv_file:
            encrypted_iv = iv_file.read()  
            print(f"#Client# Successfully loaded the encrypted IV for {current_username}")
    except FileNotFoundError:
        print(f"#Client# Error: Failed to find IV file for {current_username}")
        return None, None

    # Decrypt the session key and IV
    decrypted_session_key = decrypt_AES(encrypted_session_key, current_local_encryption_key)
    decrypted_iv = decrypt_AES(encrypted_iv, current_local_encryption_key)

    print(f"#Client# Successfully decrypted session key and IV")

    # update the global variables with current session key and iv
    current_session_key = decrypted_session_key
    current_iv = decrypted_iv
    return decrypted_session_key, decrypted_iv

def logout_user(): # Removes user's stored global information
    global current_username
    current_username = None
    global current_local_encryption_key
    current_local_encryption_key = None
    global current_session_key
    current_session_key = None
    global current_iv
    current_iv = None
    global current_salt
    current_salt = None
    return True
      
def ClientFunctions(account):
    current_username = get_logged_in_username()
    global current_local_encryption_key
    global current_session_key
    global current_iv

    # Display possible user functions
    while True:
        print("\nSelect a function:")
        print("1. Apply for loan")
        print("2. Send money - Implemented with session key encryption")
        print("3. Check balance")
        print("4. Get transaction history - Implemented")
        print("5. Pay bills")
        print("6. Set recurring payments")
        print("7. Change account settings/personal information")
        print("8. Communicate with bank representatives - Implemented with session key encryption")
        print("9. Logout")

        choice = input("Enter your choice: ")

        if choice == '1':
            # Apply for loan function (not implemented)
            print("#Client# Apply for loan function called")
           
        elif choice == '2':
            # Send money function (implemented)
            print("#Client# Send money function called")
            receiver = input("Enter receiver's username: ")
            amount = input("Enter amount to send in $: ")
            
            # Encrypt info using client-server session key (session key is in the global variable)
            encrypted_receiver = encrypt_message_gcm(receiver, current_session_key, current_iv)
            encrypted_amount = encrypt_message_gcm(amount, current_session_key, current_iv)
            encrypted_sender = encrypt_message_gcm(current_username, current_session_key, current_iv)
            print("#Client# All encryptions complete")

            # send encrypted transfer request to server
            if (transfer_money(sender=encrypted_sender, receiver=encrypted_receiver, 
                               amount=encrypted_amount)):
                print("#Client# Transfer complete")
            else:
                print("#Client# Transfer failed")

        elif choice == '3':
            # Check balance function details (not implemented)
            print("#Client# Check balance function called")
            
        elif choice == '4':
            # Get transaction history function details (implemented)
            print(f"#Client# requesting transactions for {current_username}...")

            # send encrypted requested to get all current user tranactions
            encrypted_username = encrypt_message_gcm(current_username, current_session_key, current_iv)
            user_transactions = request_transactions(encrypted_username)

            # receive encrypted
            print(f"#Client# transactions : {user_transactions}")
           
        elif choice == '5':
            # Pay bills function details (not implemented)
            print("#Client# Pay bills function called")
            
        elif choice == '6':
            # Set recurring payments function details (not implemented)
            print("#Client# Set recurring payments function called")
           
        elif choice == '7':
            # Change account settings/personal information function details (not implemented)
            print("#Client# Change account settings/personal information function called")
         
        elif choice == '8':
             # Communicate with bank representatives function details (implemented)
            print("#Client# Communicating with bank representatives...")

            receiver = 'SERVER'
            message = input("Enter your message: ")
            
            # Encrypt info using client-server session key
            encrypted_receiver = encrypt_message_gcm(receiver, current_session_key, current_iv)
            encrypted_message = encrypt_message_gcm(message, current_session_key, current_iv)
            encrypted_sender = encrypt_message_gcm(current_username, current_session_key, current_iv)
            
            # Send the encrypted message request to the server
            send_message(sender_username=encrypted_sender, 
                        receiver_username=encrypted_receiver, 
                        message=encrypted_message)
            
            print("#Client# Your message has been sent to the bank representatives. We will inform you once a representative has taken your case.")
        elif choice == '9':
            logout_user()
            break
        else:
            print("Invalid choice. Please try again.")

def EmployeeFunctions(account):
    current_username = get_logged_in_username()
    global current_session_key
    global current_iv

    # Display possible employee functions
    while True:
        print("\nSelect a function:")
        print("1. Receive/respond to user messages - Implemented with session key encryption")
        print("2. Deposit, withdraw, or transfer on behalf of customers.")
        print("3. Access account information for clients")
        print("4. Update account information for clients")
        print("5. Monitor transactions - Implemented")
        print("6. Logout")

        choice = input("Enter your choice: ")
        if choice == '1':
            # Receive/respond to user messages function details (implemented)
            print("#CLIENT# Requesting all messages from server...")

            user_messages = request_all_messages()  # Receive encrypted messages from the server
            print("#CLIENT# Received all messages.")

            decrypted_messages = []
            for message in user_messages:
                try:
                    decrypted_sender = decrypt_message_gcm(message["sender_username"], current_session_key)
                    print("decrypted sender: ", decrypted_sender)
                    decrypted_receiver = decrypt_message_gcm(message["receiver_username"], current_session_key)
                    print("decrypted receiver: ", decrypted_receiver)
                    decrypted_message = decrypt_message_gcm(message["message"], current_session_key)
                    
                    decrypted_messages.append({
                        "sender_username": decrypted_sender,
                        "receiver_username": decrypted_receiver,
                        "message": decrypted_message
                    })
                except Exception as e:
                    print(f"#CLIENT# Error decrypting message: {e}")
                    continue  # Skip this message if decryption fails

            print("#Client# Successfully decrypted all messages.")
            print(f"#Client# #Decrypted Messages: {decrypted_messages}")  # You can format this for better readability

        elif choice == '2':
            # Deposit, withdraw, or transfer money (not implemented)
            print("#Client# Deposit, withdraw, or transfer money function called")
        elif choice == '3':
            # Access client account information (not implemented)
            print("#Client# Access client account information function called")
            print("#Client# Employee can view all the client's account information, unencrypted")
        elif choice == '4':
            # Update client account information (not implemented)
            print("#Client# Update client account information function called")
        elif choice == '5':
            # Monitor client transactions (implemented)
            print("#Client# Monitor client transactions function called")
            user_transactions = request_all_transactions() # request all transactions from server
            print(f"#Client# Received all transactions.")
            print(f"#Client# User transactions: {user_transactions}") 
            # Assume the exchange was encrypted using the session key (like in choice 1)
        elif choice == '6':
            logout_user()
            return
        else:
            print("Invalid choice. Please try again.")

def AdminFunctions(account):
    current_username = get_logged_in_username()
    global current_session_key
    global current_iv

    while True:
        print("\nSelect a function:")
        print("1. Manage user roles, permissions, and access controls")
        print("2. Implement security measures")
        print("3. Handle cryptographic key generation, distribution, and storage")
        print("4. Apply updates, patches, and perform regular system backups")
        print("5. Logout")

        choice = input("Enter your choice: ")

        if choice == '1':
            # Manage user roles, permissions, and access controls function details (not implemented)
            print("Manage user roles, permissions, and access controls function called")
        elif choice == '2':
            # Implement security measures function details (not implemented)
            print("Implement security measures function called")
        elif choice == '3':
            # Handle cryptographic key generation, distribution, and storage function details (not implemented)
            print("Handle cryptographic key generation, distribution, and storage function called")
        elif choice == '4':
            # Apply updates, patches, and perform regular system backups function details (not implemented)
            print("Apply updates, patches, and perform regular system backups function called")
        elif choice == '5':
            logout_user()
            return
        else:
            print("Invalid choice. Please try again.")

def main():
      
      print("Welcome to the Bank!")

      # Create folders and ensure they exist (for future use)
      os.makedirs("client_public_keys_CLIENT_SIDE_DEL", exist_ok=True)
      os.makedirs("client_private_keys_CLIENT_SIDE_DEL", exist_ok=True)
      os.makedirs("session_keys_CLIENT_SIDE_DEL", exist_ok=True)
     
     # register_static_users() # REMOVE COMMENT TO CREATE 1 EMP, 1 USER, 1 ADMIN, already created
    
      while True:
              
              print("\nType 'login' to sign in, 'register' to signup, or 'exit' to quit.")
              choice = input("Enter your choice: ").lower()

              if choice == "exit":
                  print("Goodbye! Thank you for using the Bank.")
                  break  
              
              elif choice == "login": # start login process
              
                  print("#Client#")
                  username = input("Enter your username: ")
                  password = input("Enter your password: ")

                  # Combine username and password for encryption (in bytes)
                  combined_data = f"{username}:{password}".encode()  

                  # encrypt the credentials using server's public key
                  encrypted_login_credentials = encrypt_with_server_public_key(combined_data)

                  otp, account = login(encrypted_login_credentials)  # Call login function

                  if not account:
                      print("#Client# Login failed. Please try again.\n")
                      continue  # Restart loop on failed login

                  print(f"#Client# Your OTP is: {otp}")      
                  entered_otp = input(" Enter the OTP received: ") # verify otp
                  while entered_otp != otp:
                        print("#Client# Incorrect OTP. Login failed.")
                        entered_otp = input("#Client# Enter the OTP received or type 'exit' to restart login: ")
                        if entered_otp == "exit":
                            break  # Restart the loop if user types 'exit'
                         
                  account_role = account.get("role") # determine current user's role
                  print("=" * 40)  
                  print("Login Successful!")
                  print(f"Logged in as: {account_role}")
                  set_logged_in_username(username) # set current username to username

                  # load the session key for future use
                  session_key, iv = load_session_key(current_username=username, password=password)
                  
                  # Call role-specific functions
                  if account_role == "admin":
                      AdminFunctions(account)
                  elif account_role == "employee":
                      EmployeeFunctions(account)
                  elif account_role == "client":
                      ClientFunctions(account)
                  else:
                      print("Invalid role. Please contact support.")

                  print("#Client# \nLogging out...\n")
                  print("=" * 40)  

              elif choice == "register":
                # get input on account details
                print("#Client#")

                # input username
                username = input("Enter username: ")

                # input password
                print("Password must be at least 6 characters and contain at least one uppercase letter, one lowercase letter, and one special character.")
                password = input("Enter password: ")
                # Ensure password meets requirements
                while len(password) < 6 or not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char in "!@#$%^&*()-_+=~`[]{}|:;'<>,.?/" for char in password):
                    print("#Client# Password does not meet requirements. Please try again.")
                    password = input("Enter password: ")

                #input email
                email = input ("Enter email: ")

                #input account level
                account_level = input("Enter account level (user, admin, employee): ").lower()

                #input status
                status = "active"

                # Register the user
                register_user(username, password, email, account_level, status)
                print("#Client# Account created successfully.")

              else:
                  print("#Client# Invalid choice. Please type 'login' or 'exit'.")

if __name__ == "__main__":
    main()
