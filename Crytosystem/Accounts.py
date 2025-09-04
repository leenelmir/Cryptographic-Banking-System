# ALL USER CLASSES
from Encryptions import generate_rsa_keys, decrypt_AES
from Encryptions import encrypt_AES, decrypt_AES_master, encrypt_message_gcm

import uuid
import json
import os
import base64
from datetime import datetime
from Crypto.Cipher import AES

# global variables to hold the current user's session key and iv
current_session_key = None
current_iv = None 

# Parent class: all clients, employees, and admins inherit from this class
class User:
    def __init__(self, username, password, email, status, role, public_key):
        self.username = username
        self.password = password
        self.public_key = public_key 
        self.email = email
        self.status = status # possible values: deleted, frozen, active
        self.role = role if role else "user"

# Client class used to create users
class ClientAccount(User): 
    def __init__(self, username, password, email, status, public_key, account_number=None, account_balance=0.0):
        super().__init__(username, password, email, status, "client", public_key=public_key)
        # clients also have account numbers and account balance
        self.account_number = account_number if account_number else str(uuid.uuid4())  # Generate unique account number if not provided
        self.account_balance = account_balance  

# Employee class used to create employees
class EmployeeAccount(User):
    def __init__(self, username, password, email, status, public_key):
        super().__init__(username, password, email, status, "employee", public_key=public_key)

# Admin class used to create admins
class AdminAccount(User):
    def __init__(self, username, password, email, status, public_key):
        super().__init__(username, password, email, status, "admin", public_key=public_key)

# called from client side, simulating being called through a socket
def log_transaction(sender, receiver, amount, filename="transactions_SERVER_SIDE_DEL.json"):
    
    # retrieve aes master key
    aes_master_key = decrypt_AES_master() 

    # encrypt current time    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_timestamp = encrypt_AES(timestamp, aes_master_key)

    # encrypt sender username
    encrypted_sender = encrypt_AES(sender, aes_master_key)
    print(f"#Server# sender log : {sender}")
    print(f"#Server# encrypted sender log : {encrypted_sender}")

    # encrypt receiver username
    encrypted_receiver = encrypt_AES(receiver, aes_master_key)

    # encrypt transferred amount
    encrypted_amount = encrypt_AES(str(amount), aes_master_key)
    
    # Convert bytes to string using Base64
    transaction = {
        "timestamp": base64.b64encode(encrypted_timestamp).decode('utf-8'),
        "sender_username": base64.b64encode(encrypted_sender).decode('utf-8'),
        "receiver_username": base64.b64encode(encrypted_receiver).decode('utf-8'),
        "amount": base64.b64encode(encrypted_amount).decode('utf-8')
    }

    # Load existing transactions
    transactions = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                transactions = json.load(f)
            except json.JSONDecodeError:
                transactions = []  # If file is empty or corrupt

    # Append new transaction to list
    transactions.append(transaction)

    # Save updated transactions back to JSON file
    with open(filename, "w") as f:
        json.dump(transactions, f, indent=4)

    print("#Server# Transaction successfully logged.")
    return True

# called from client side, simulating being called through a socket
def request_transactions(username, filename="transactions_SERVER_SIDE_DEL.json"):
    
    # Load all transactions from the JSON file
    global current_session_key

    # decrypt username making request
    username = decrypt_AES(username, current_session_key)
    print(f"#Server# requesting transactions for {username}")

    # Read from the transactions file
    transactions = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                transactions = json.load(f)
            except json.JSONDecodeError:
                print("#Server# Error reading transactions. File may be corrupt.")
                return []

    aes_master_key = decrypt_AES_master()    
    # Decrypt the transactions and filter by username
    filtered_transactions = []
    for transaction in transactions:
        # Decrypting each field
        try:
            decrypted_timestamp = decrypt_AES(base64.b64decode(transaction["timestamp"]), aes_master_key)
            decrypted_sender = decrypt_AES(base64.b64decode(transaction["sender_username"]), aes_master_key)
            decrypted_receiver = decrypt_AES(base64.b64decode(transaction["receiver_username"]), aes_master_key)
           
            decrypted_amount = decrypt_AES(base64.b64decode(transaction["amount"]), aes_master_key)

            # Check if the sender or receiver matches the username
            if decrypted_sender == username or decrypted_receiver == username:
                filtered_transactions.append({
                    "timestamp": decrypted_timestamp,
                    "sender": decrypted_sender,
                    "receiver": decrypted_receiver,
                    "amount": decrypted_amount
                })
        except Exception as e:
            print(f"#Server# Error decrypting transaction: {e}")
            continue  # Skip transaction

    return filtered_transactions

# called from client side, simulating being called through a socket
def request_all_transactions(filename="transactions_SERVER_SIDE_DEL.json"):
       # Load all transactions from transactions JSON file
    print("#Server# Verified account is an employee")   
    print("#Server# Requesting all client transactions")

    # Read transactions file
    transactions = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                transactions = json.load(f)
            except json.JSONDecodeError:
                print("#Server# Error reading transactions. File may be corrupt.")
                return []

    # retrieve master key
    aes_master_key = decrypt_AES_master()    

    # Decrypt the transactions and filter by username
    decrypted_transactions = []
    for transaction in transactions:
        # Decrypting each field
        try:
            decrypted_timestamp = decrypt_AES(base64.b64decode(transaction["timestamp"]), aes_master_key)
            decrypted_sender = decrypt_AES(base64.b64decode(transaction["sender_username"]), aes_master_key)
            decrypted_receiver = decrypt_AES(base64.b64decode(transaction["receiver_username"]), aes_master_key)  
            decrypted_amount = decrypt_AES(base64.b64decode(transaction["amount"]), aes_master_key)

            decrypted_transactions.append({
                "timestamp": decrypted_timestamp,
                "sender": decrypted_sender,
                "receiver": decrypted_receiver,
                "amount": decrypted_amount
            })
        except Exception as e:
            print(f"Error decrypting transaction: {e}")
            continue  # Skip transaction

    return decrypted_transactions

# called from server side, to log a message being sent
def log_message(sender, receiver, message, filename="messages_SERVER_SIDE_DEL.json"):
    
    # decrypt aes master key
    aes_master_key = decrypt_AES_master() 

    # encrypt using the aes master key
    encrypted_sender = encrypt_AES(sender, aes_master_key)
    encrypted_receiver = encrypt_AES(receiver, aes_master_key)
    encrypted_message = encrypt_AES(message, aes_master_key)
    
    # Convert bytes to string using Base64
    message = {
        "sender_username": base64.b64encode(encrypted_sender).decode('utf-8'),
        "receiver_username": base64.b64encode(encrypted_receiver).decode('utf-8'),
        "message": base64.b64encode(encrypted_message).decode('utf-8')
    } 

    # Load existing messages
    messages = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                messages = json.load(f)
            except json.JSONDecodeError:
                messages = []  # If file is empty or corrupt

    # Append new message to list
    messages.append(message)

    # Save updated messages back to JSON file
    with open(filename, "w") as f:
        json.dump(messages, f, indent=4)

    print("#Server# Message successfully logged.")
    return True

# called from client side, simulating being called through a socket
def request_all_messages(filename="messages_SERVER_SIDE_DEL.json"):
    global current_session_key
    global current_iv

       # Load all transactions from the JSON file
    print("#Server# Verified account is an employee.")   
    print(f"#Server# Requesting all client messages")

    # Read messages from JSON file
    messages = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                messages = json.load(f)
            except json.JSONDecodeError:
                print("#Server# Error reading message. File may be corrupt.")
                return []

    # decrypt aes master key
    aes_master_key = decrypt_AES_master()   

    # Decrypt the messages and filter by username
    decrypted_messages = []
    for message in messages:
        # Decrypting each field
        try:
            decrypted_sender = decrypt_AES(base64.b64decode(message["sender_username"]), aes_master_key)
            decrypted_receiver = decrypt_AES(base64.b64decode(message["receiver_username"]), aes_master_key)  
            decrypted_message = decrypt_AES(base64.b64decode(message["message"]), aes_master_key)

            decrypted_messages.append({
                "sender_username": decrypted_sender,
                "receiver_username": decrypted_receiver,
                "message": decrypted_message
            })
        except Exception as e:
            print(f"#Server# Error decrypting message: {e}")
            continue  # Skip message

    # Encrypt the messages using the current session key
    encrypted_messages = []
    for message in decrypted_messages:
        try:
            sender_data = message["sender_username"]
            receiver_data = message["receiver_username"]
            message_data = message["message"]
        
            encrypted_sender = encrypt_message_gcm(sender_data, current_session_key, current_iv)
            encrypted_receiver = encrypt_message_gcm(receiver_data, current_session_key, current_iv)
            encrypted_message = encrypt_message_gcm(message_data, current_session_key, current_iv)
          
            encrypted_messages.append({
                "sender_username": encrypted_sender,
                "receiver_username": encrypted_receiver,
                "message": encrypted_message
            })
        except Exception as e:
            print(f"#Server# Error encrypting message: {e}")
            continue  # Skip message 

    return encrypted_messages

# called from server side, to set the session key and iv in this file too
def share_session_key(session_key, iv):
    global current_session_key
    global current_iv
    current_session_key = session_key
    current_iv = iv
    return True