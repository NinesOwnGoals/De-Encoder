import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from tkinter import Tk, simpledialog, messagebox, Button
from tkinter.filedialog import askopenfilename, asksaveasfilename

def generate_key(password: str, salt: bytes) -> bytes:
    """Erzeugt einen Schlüssel aus einem Passwort und einem Salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    """Verschlüsselt eine Datei mit einem Passwort."""
    salt = os.urandom(16)  # Zufälliges Salt für den Schlüssel
    key = generate_key(password, salt)
    fernet = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            data = file.read()

        encrypted_data = fernet.encrypt(data)

        # Ziel-Dateipfad für die verschlüsselte Datei
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as file:
            file.write(salt + encrypted_data)  # Salt und verschlüsselte Daten speichern

        messagebox.showinfo("Erfolg", f"Datei erfolgreich verschlüsselt: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler beim Verschlüsseln der Datei: {e}")

def decrypt_file(file_path: str, password: str):
    """Entschlüsselt eine Datei mit einem Passwort."""
    try:
        with open(file_path, "rb") as file:
            salt = file.read(16)  # Das Salt aus der verschlüsselten Datei lesen
            encrypted_data = file.read()

        key = generate_key(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data)

        # Ziel-Dateipfad für die entschlüsselte Datei
        original_file_path = file_path.replace(".enc", "")
        with open(original_file_path, "wb") as file:
            file.write(decrypted_data)  # Entschlüsselte Daten speichern

        messagebox.showinfo("Erfolg", f"Datei erfolgreich entschlüsselt: {original_file_path}")
    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler beim Entschlüsseln der Datei: {e}")

def select_file_for_encryption():
    """Öffnet einen Datei-Explorer für die Verschlüsselung."""
    file_path = askopenfilename(title="Wähle eine Datei zum Verschlüsseln")
    if file_path:
        password = simpledialog.askstring("Passwort", "Gib ein Passwort ein:", show='*')
        if password:
            encrypt_file(file_path, password)

def select_file_for_decryption():
    """Öffnet einen Datei-Explorer für die Entschlüsselung."""
    file_path = askopenfilename(title="Wähle eine verschlüsselte Datei zum Entschlüsseln", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = simpledialog.askstring("Passwort", "Gib das Passwort ein:", show='*')
        if password:
            decrypt_file(file_path, password)

def create_gui():
    """Erstellt die grafische Benutzeroberfläche (GUI)."""
    root = Tk()
    root.title("Datei Verschlüsselung/Entschlüsselung")

    # Schaltfläche zum Verschlüsseln
    encrypt_button = Button(root, text="Datei verschlüsseln", width=20, command=select_file_for_encryption)
    encrypt_button.pack(pady=10)

    # Schaltfläche zum Entschlüsseln
    decrypt_button = Button(root, text="Datei entschlüsseln", width=20, command=select_file_for_decryption)
    decrypt_button.pack(pady=10)

    # Fenster starten
    root.mainloop()

if __name__ == "__main__":
    create_gui()
