import google.generativeai as genai
from django.conf import settings

def get_gemini_response(prompt):
    genai.configure(api_key=settings.GEMINI_API_KEY)

    model = genai.GenerativeModel('gemini-2.0-flash')
    response = model.generate_content(prompt)

    return response.text