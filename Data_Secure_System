import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet  # ✅ This is used properly below

# ----------------------- Constants & File Paths -----------------------

DATA_FILE = "data.json"
KEY_FILE = "fernet.key"
MASTER_PASSWORD = "admin123"  # Change for production

# ----------------------- Key Setup -----------------------

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        return key

# Load encryption key and cipher
key = load_or_create_key()
cipher = Fernet(key)

# ----------------------- Utility Functions -----------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, stored_data):
    hashed = hash_passkey(passkey)

    for key, value in stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# ----------------------- Session State Init -----------------------

if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False

# ----------------------- Streamlit Page Config -----------------------

st.set_page_config(page_title="🔐 Secure Data Encryption", layout="centered")
st.sidebar.title("🔐 Navigation")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Go to", menu)

# ----------------------- Pages -----------------------

if choice == "Home":
    st.title("🔒 Secure Data Encryption System (with JSON)")
    st.markdown("""
    Welcome to your secure data locker.  
    - Encrypt and store any sensitive information.  
    - Use your unique passkey to decrypt it later.  
    - All data is stored **securely** and **persistently** in a JSON file.
    """)

# ----------------------- STORE DATA -----------------------

elif choice == "Store Data":
    st.header("📂 Store Your Data Securely")

    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Create a passkey to protect this data:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)

            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }

            save_data(st.session_state.stored_data)

            st.success("✅ Your data was encrypted and saved securely!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please provide both data and a passkey.")

# ----------------------- RETRIEVE DATA -----------------------

elif choice == "Retrieve Data":
    st.header("🔍 Retrieve Your Encrypted Data")

    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts. Redirecting to Login...")
        st.switch_page("Login")  # Or: st.experimental_rerun()
    
    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey, st.session_state.stored_data)

            if result:
                st.success("✅ Decryption Successful!")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
        else:
            st.warning("⚠️ Please enter both encrypted data and your passkey.")

# ----------------------- LOGIN PAGE -----------------------

elif choice == "Login":
    st.header("🔑 Reauthorization Required")

    login_pass = st.text_input("Enter master password to unlock:", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Reauthorized! You can now try to retrieve data again.")
        else:
            st.error("❌ Incorrect master password.")
