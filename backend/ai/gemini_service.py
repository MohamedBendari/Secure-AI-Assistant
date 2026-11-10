
import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.7-flash"
)

if not API_KEY:
    raise RuntimeError("GEMINI_API_KEY is missing from .env")

client = genai.Client(
    api_key=API_KEY,
    http_options=types.HttpOptions(
        timeout=60000
    )
)


def generate_ai_response(prompt: str) -> str:

    if not prompt or not prompt.strip():
        raise ValueError("Prompt cannot be empty")

    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )

        if not response.text:
            raise RuntimeError("Gemini returned an empty response")

        return response.text

    except Exception as error:
        print(f"Gemini API Error: {error}")
        raise
