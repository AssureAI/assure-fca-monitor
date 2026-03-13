import os
import requests

MODEL = "gpt-4.1-mini"


def get_rule_guidance(prompt: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "LLM not configured."

    try:
        r = requests.post(
            "https://api.openai.com/v1/responses",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "input": prompt,
                "max_output_tokens": 300,
            },
            timeout=20,
        )

        if not r.ok:
            return f"OpenAI error {r.status_code}: {r.text[:500]}"

        data = r.json()

        # Try convenience field first
        text = (data.get("output_text") or "").strip()
        if text:
            return text

        # Fallback: parse structured output
        parts = []
        for item in data.get("output", []):
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    t = (content.get("text") or "").strip()
                    if t:
                        parts.append(t)

        if parts:
            return "\n\n".join(parts)

        return f"OpenAI success but no text content: {str(data)[:500]}"

    except Exception as e:
        return f"LLM request failed: {str(e)[:500]}"
