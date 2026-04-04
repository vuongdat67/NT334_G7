import json
import os
import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from openai import OpenAI


class LLMClient:
    @staticmethod
    def _is_local_base_url(base_url: Optional[str]) -> bool:
        if not base_url:
            return False
        host = (urlparse(base_url).hostname or "").lower()
        if host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
            return True
        if host.startswith("10.") or host.startswith("192.168."):
            return True
        if host.startswith("172."):
            parts = host.split(".")
            if len(parts) > 1 and parts[1].isdigit():
                second = int(parts[1])
                return 16 <= second <= 31
        return False

    @classmethod
    def _resolve_api_key(cls, api_key_env: str, base_url: Optional[str]) -> str:
        api_key = os.getenv(api_key_env)
        if api_key:
            return api_key
        if cls._is_local_base_url(base_url):
            # OpenAI-compatible local servers often ignore auth but SDK requires a key field.
            return "local-not-needed"
        raise EnvironmentError(f"{api_key_env} is not set.")

    def __init__(
        self,
        model: str,
        temperature: float = 0.0,
        api_key_env: str = "OPENAI_API_KEY",
        base_url: Optional[str] = None,
        timeout_seconds: float = 30.0,
        max_output_tokens: Optional[int] = 400,
        force_json_response_format: bool = True,
        reasoning_enabled: Optional[bool] = None,
    ):
        api_key = self._resolve_api_key(api_key_env, base_url)

        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_seconds)
        self.model = model
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.force_json_response_format = force_json_response_format
        self.reasoning_enabled = reasoning_enabled

    def list_model_ids(self) -> List[str]:
        response = self.client.models.list()
        return [m.id for m in response.data if getattr(m, "id", None)]

    def _repair_to_json(self, raw_text: str) -> Optional[Dict[str, Any]]:
        try:
            req: Dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a strict JSON formatter. "
                            "Return only valid JSON, no markdown, no prose."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            "Convert the following model output into this schema exactly: "
                            "{\"suspicious_processes\": [{\"pid\": 0, \"process_name\": \"\", "
                            "\"reason\": \"\", \"confidence\": 0.0}]}. "
                            "If no valid suspicious processes are present, return "
                            "{\"suspicious_processes\": []}.\n\n"
                            f"Raw output:\n{raw_text}"
                        ),
                    },
                ],
                "temperature": 0,
                "max_tokens": 220,
                "response_format": {"type": "json_object"},
            }
            resp = self.client.chat.completions.create(**req)
            text = (resp.choices[0].message.content or "").strip()
            return self._extract_json(text)
        except Exception:
            return None

    def ping(self, prompt: str = "Reply with exactly: HEALTHY") -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        return (resp.choices[0].message.content or "").strip()

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict[str, Any]]:
        stripped = text.strip()
        if not stripped:
            return None

        # Direct JSON parse first.
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

        # Try markdown fenced block: ```json ... ```
        fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", stripped)
        if fenced:
            try:
                data = json.loads(fenced.group(1))
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        # Fallback: first JSON object in text.
        first_brace = stripped.find("{")
        last_brace = stripped.rfind("}")
        if first_brace != -1 and last_brace != -1 and first_brace < last_brace:
            candidate = stripped[first_brace : last_brace + 1]
            try:
                data = json.loads(candidate)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                return None
        return None

    def triage_once(self, prompt: str) -> Dict[str, Any]:
        try:
            req: Dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Return only valid JSON. Do not include markdown, "
                            "reasoning tags, or any text outside the JSON object."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                "temperature": self.temperature,
            }
            if self.max_output_tokens is not None:
                req["max_tokens"] = self.max_output_tokens

            if self.reasoning_enabled is not None:
                req["extra_body"] = {"reasoning": {"enabled": self.reasoning_enabled}}

            if self.force_json_response_format:
                req["response_format"] = {"type": "json_object"}

            try:
                resp = self.client.chat.completions.create(**req)
            except Exception:
                # Some local OpenAI-compatible servers may not support response_format.
                if "response_format" in req:
                    req.pop("response_format", None)
                    resp = self.client.chat.completions.create(**req)
                else:
                    raise
        except Exception as e:  # noqa: BLE001
            return {
                "suspicious_processes": [],
                "api_error": str(e),
            }

        text = (resp.choices[0].message.content or "").strip()
        if not text:
            return {"suspicious_processes": []}

        parsed = self._extract_json(text)
        if parsed is not None:
            parsed.setdefault("suspicious_processes", [])
            return parsed

        repaired = self._repair_to_json(text)
        if repaired is not None:
            repaired.setdefault("suspicious_processes", [])
            repaired["repaired_json"] = True
            return repaired

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
