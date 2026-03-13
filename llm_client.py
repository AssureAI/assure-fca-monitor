import os
from openai import OpenAI

MODEL = "gpt-4.1-mini"


def get_rule_guidance(prompt: str) -> str:

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "LLM not configured."

    try:
        client = OpenAI(api_key=api_key)

        r = client.responses.create(
            model=MODEL,
            input=prompt,
            max_output_tokens=300,
        )

        return r.output_text.strip()

    except Exception:
        return "Unable to generate guidance."
