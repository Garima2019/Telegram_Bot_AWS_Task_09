import requests
import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")      # NEW

def ask_groq(question: str) -> str:
    if not GROQ_API_KEY:
        return "Groq is not configured."
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GROQ_API_KEY.strip()}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": question}
        ],
        "max_tokens": 1024
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.text}")
        return f"Groq API error: {e.response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"