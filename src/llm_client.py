import json
import os
from typing import Any, Dict, List

from openai import OpenAI


class LLMClient:
    def __init__(self, model: str, temperature: float = 0.0):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY is not set.")

        base_url = os.getenv("OPENAI_BASE_URL")
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.temperature = temperature

    def triage_once(self, prompt: str) -> Dict[str, Any]:
        resp = self.client.responses.create(
            model=self.model,
            input=prompt,
            temperature=self.temperature,
        )

        text = resp.output_text.strip()
        if not text:
            return {"suspicious_processes": []}

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "suspicious_processes": [],
                "raw_response": text,
                "parse_error": True,
            }


def majority_vote(votes: List[dict]) -> dict:
    # Placeholder strategy: pick the result with the largest suspicious set.
    # This will be replaced by PID-level voting in the next iteration.
    if not votes:
        return {"suspicious_processes": []}
    return max(votes, key=lambda x: len(x.get("suspicious_processes", [])))
