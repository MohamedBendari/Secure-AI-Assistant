
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
model = os.getenv("GEMINI_MODEL", "gemini-3.7-flash")

if not api_key:
    raise ValueError("GEMINI_API_KEY is missing from .env")

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model=model,
    contents="Hello! Introduce yourself briefly."
)

print("Gemini Connection Successful!")
print("Model:", model)
print("Response:", response.text)

client.close()
