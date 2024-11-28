# Datei Verschlüsselung/Entschlüsselung

Dieses Python-Skript bietet eine grafische Benutzeroberfläche (GUI) zur Verschlüsselung und Entschlüsselung von Dateien mit einem Passwort. Es nutzt die **PBKDF2-HMAC**-KDF (Key Derivation Function) aus der Bibliothek **cryptography**, um einen sicheren Schlüssel zu erzeugen, und verwendet **Fernet** zur symmetrischen Verschlüsselung von Daten.

## Anforderungen

Für die Ausführung dieses Skripts müssen die folgenden Python-Bibliotheken installiert sein:

cryptography
tkinter

### Python-Bibliotheken

Stelle sicher, dass alle benötigten Bibliotheken installiert sind. Du kannst die Anforderungen einfach mit dem folgenden Befehl installieren:

```bash
pip install -r requirements.txt
