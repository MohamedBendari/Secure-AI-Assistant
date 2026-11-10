
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key)

print("Available Gemini models:\n")

for model in client.models.list():
    actions = getattr(model, "supported_actions", []) or []

    if "generateContent" in actions:
        print(model.name)

client.close()


# to run in terminal ----> python -m tests.list_gemini_models