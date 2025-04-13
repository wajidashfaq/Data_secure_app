import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# -------------------- Constants & File Paths --------------------

DATA_FILE = "user_data.json"
KEY_FILE = "fernet.key"

# -------------------- Fernet Setup --------------------

def get_cipher():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

cipher = get_cipher()

# -------------------- Utility Functions --------------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# -------------------- Session State --------------------

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# -------------------- App Pages --------------------

st.set_page_config(page_title="Secure Data System", layout="centered")
menu = ["Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("🔐 Navigation", menu)

# -------------------- Register Page --------------------

if choice == "Register":
    st.title("📝 Register")

    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        data = load_data()

        if username in data:
            st.error("❌ Username already exists. Choose another.")
        elif username and password:
            data[username] = {
                "password": hash_password(password),
                "entries": []
            }
            save_data(data)
            st.success("✅ Registration successful! You can now login.")
        else:
            st.warning("⚠️ Please fill in both fields.")

# -------------------- Login Page --------------------

elif choice == "Login":
    st.title("🔐 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        data = load_data()
        if username in data and data[username]["password"] == hash_password(password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid credentials.")

# -------------------- Store Data --------------------

elif choice == "Store Data":
    st.title("📂 Store Encrypted Data")

    if not st.session_state.logged_in:
        st.warning("🔒 You must log in first.")
    else:
        user_data = st.text_area("Enter the data you want to encrypt and store:")

        if st.button("Encrypt & Store"):
            if user_data:
                encrypted = encrypt_data(user_data)
                data = load_data()
                data[st.session_state.username]["entries"].append(encrypted)
                save_data(data)
                st.success("✅ Data encrypted and stored successfully.")
                st.code(encrypted, language="text")
            else:
                st.warning("⚠️ Please enter some data to store.")

# -------------------- Retrieve Data --------------------

elif choice == "Retrieve Data":
    st.title("🔍 Retrieve Your Stored Data")

    if not st.session_state.logged_in:
        st.warning("🔒 You must log in first.")
    else:
        data = load_data()
        entries = data[st.session_state.username]["entries"]

        if entries:
            selected = st.selectbox("Select encrypted entry:", entries)
            if st.button("Decrypt"):
                decrypted = decrypt_data(selected)
                st.success("✅ Decrypted Data:")
                st.code(decrypted)
        else:
            st.info("ℹ️ No encrypted entries found for your account.")
