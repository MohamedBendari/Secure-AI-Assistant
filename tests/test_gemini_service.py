
from backend.ai.gemini_service import generate_ai_response

prompt = "What is AI? Answer in one short sentence."

print("Sending request to Gemini...")

try:
    response = generate_ai_response(prompt)

    print("\nGemini Response:")
    print(response)

    print("\nGemini Service Test Passed!")

except Exception as error:
    print("\nGemini Service Test Failed!")
    print("Error:", error)
