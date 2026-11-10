
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

key = os.getenv("ENCRYPTION_KEY")

if not key:
    raise RuntimeError(
        "ENCRYPTION_KEY is missing from .env"
    )

fernet = Fernet(key.encode())


def encrypt_data(data: str) -> str:
    encrypted = fernet.encrypt(data.encode())
    return encrypted.decode()


def decrypt_data(encrypted_data: str) -> str:
    decrypted = fernet.decrypt(encrypted_data.encode())
    return decrypted.decode()
