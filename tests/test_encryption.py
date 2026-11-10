
from backend.security.encryption import (
    encrypt_data,
    decrypt_data
)

sensitive_data = "Mohamed@example.com"

encrypted = encrypt_data(sensitive_data)
decrypted = decrypt_data(encrypted)

print("Original Data:", sensitive_data)
print("Encrypted Data:", encrypted)
print("Decrypted Data:", decrypted)

assert decrypted == sensitive_data

print("Encryption Test Passed!")
