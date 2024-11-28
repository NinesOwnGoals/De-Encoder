import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from tkinter import Tk, simpledialog, messagebox, Button
from tkinter.filedialog import askopenfilename, asksaveasfilename

def generate_key(password: str, salt: bytes) -> bytes:
    """Generates a key from a password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    """Encrypts a file with a password."""
    salt = os.urandom(16)  
    key = generate_key(password, salt)
    fernet = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            data = file.read()

        encrypted_data = fernet.encrypt(data)

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as file:
            file.write(salt + encrypted_data)  

        messagebox.showinfo("Success", f"File successfully encrypted: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error encrypting the file: {e}")

def decrypt_file(file_path: str, password: str):
    """Decrypts a file with a password."""
    try:
        with open(file_path, "rb") as file:
            salt = file.read(16) 
            encrypted_data = file.read()

        key = generate_key(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data)

        original_file_path = file_path.replace(".enc", "")
        with open(original_file_path, "wb") as file:
            file.write(decrypted_data)  

        messagebox.showinfo("Success", f"File successfully decrypted: {original_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error decrypting the file: {e}")

def select_file_for_encryption():
    """Opens a file dialog for encryption."""
    file_path = askopenfilename(title="Choose a file to encrypt")
    if file_path:
        password = simpledialog.askstring("Password", "Enter a password:", show='*')
        if password:
            encrypt_file(file_path, password)

def select_file_for_decryption():
    """Opens a file dialog for decryption."""
    file_path = askopenfilename(title="Choose an encrypted file to decrypt", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = simpledialog.askstring("Password", "Enter the password:", show='*')
        if password:
            decrypt_file(file_path, password)

def create_gui():
    """Creates the graphical user interface (GUI)."""
    root = Tk()
    root.title("File Encryption/Decryption")

    encrypt_button = Button(root, text="Encrypt File", width=20, command=select_file_for_encryption)
    encrypt_button.pack(pady=10)

    decrypt_button = Button(root, text="Decrypt File", width=20, command=select_file_for_decryption)
    decrypt_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
