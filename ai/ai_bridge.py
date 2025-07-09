"""
AI Bridge - Interface with local Mixtral model via Ollama
Provides vulnerability intelligence and advisory capabilities
"""

import httpx
import time
import logging

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mixtral"

def ask_mixtral(prompt: str, retries: int = 2, timeout: int = 30) -> str:
    """
    Send a prompt to the local Mixtral model via Ollama and return the response string.
    Args:
        prompt (str): The prompt/question to send to Mixtral.
        retries (int): Number of retries on failure.
        timeout (int): Timeout for the HTTP request in seconds.
    Returns:
        str: The response from Mixtral, or an error message if failed.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    for attempt in range(retries + 1):
        try:
            r = httpx.post(OLLAMA_URL, json=payload, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            response = data.get("response", "").strip()
            if response:
                return response
            else:
                logging.warning(f"Mixtral returned empty response for prompt: {prompt}")
        except Exception as e:
            logging.error(f"Mixtral/Ollama request failed (attempt {attempt+1}): {e}")
            time.sleep(2)
    return "[Mixtral AI error: Unable to get response]" 