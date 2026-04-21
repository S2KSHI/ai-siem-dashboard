# ollama_lib.py

import json
import requests

class OllamaClient:
    def __init__(self, base_url="http://localhost:11434"):
        self.base_url = base_url.rstrip('/')

    def chat(self, model, messages, tools=None):
        """
        Führt einen Chat-Aufruf mit Tool-Unterstützung durch.
        
        :param model: Der zu verwendende Modellname.
        :param messages: Nachrichten für das Gespräch im Chat.
        :param tools: Eine Liste von Tools für die Tool-Calls.
        :return: Die Antwort der API.
        """
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages
        }
        
        if tools:
            payload["tools"] = tools

        headers = {"Content-Type": "application/json"}
        response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=20)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Fehler bei der LLM-Anfrage: {response.status_code} - {response.text}")

    def generate(self, prompt, model="llama3.2"):
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}]
        }
        response = requests.post(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(f"Fehler bei der LLM-Anfrage: {response.status_code} - {response.text}")

        body = response.json()
        return body.get("choices", [{}])[0].get("message", {}).get("content", "")
