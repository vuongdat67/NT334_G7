import json
import os
import re
from collections import Counter, defaultdict
from statistics import mean
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from openai import OpenAI


class LLMClient:
    @staticmethod
    def _sanitize_suspicious_items(payload: Dict[str, Any]) -> Dict[str, Any]:
        items = payload.get("suspicious_processes", [])
        if not isinstance(items, list):
            payload["suspicious_processes"] = []
            return payload

        clean = []
        for item in items:
            if not isinstance(item, dict):
                continue
            pid = item.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                continue
            clean.append(item)
        payload["suspicious_processes"] = clean
        return payload

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
            try:
                resp = self.client.chat.completions.create(**req)
            except Exception:
                # Some local OpenAI-compatible servers do not support response_format.
                req.pop("response_format", None)
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

            if self.reasoning_enabled is True:
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
            usage = getattr(resp, "usage", None)
            if usage is not None:
                parsed["usage"] = {
                    "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                    "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
                    "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
                }
            return self._sanitize_suspicious_items(parsed)

        repaired = self._repair_to_json(text)
        if repaired is not None:
            repaired.setdefault("suspicious_processes", [])
            repaired["repaired_json"] = True
            return self._sanitize_suspicious_items(repaired)

        return {
            "suspicious_processes": [],
            "raw_response": text,
            "parse_error": True,
        }


def majority_vote(votes: List[dict]) -> dict:
    if not votes:
        return {
            "suspicious_processes": [],
            "majority_vote_meta": {
                "total_runs": 0,
                "valid_runs": 0,
                "threshold": 0,
            },
        }

    valid_votes: List[Dict[str, Any]] = []
    for vote in votes:
        if not isinstance(vote, dict):
            continue
        if vote.get("api_error"):
            continue
        valid_votes.append(vote)

    if not valid_votes:
        return {
            "suspicious_processes": [],
            "majority_vote_meta": {
                "total_runs": len(votes),
                "valid_runs": 0,
                "threshold": 0,
            },
        }

    pid_support: Dict[int, int] = defaultdict(int)
    pid_items: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    for vote in valid_votes:
        suspicious = vote.get("suspicious_processes", [])
        if not isinstance(suspicious, list):
            continue

        seen_pids = set()
        for item in suspicious:
            if not isinstance(item, dict):
                continue
            pid_raw = item.get("pid")
            if not isinstance(pid_raw, int):
                continue
            if pid_raw in seen_pids:
                continue

            seen_pids.add(pid_raw)
            pid_support[pid_raw] += 1
            pid_items[pid_raw].append(item)

    threshold = (len(valid_votes) // 2) + 1

    merged_items: List[Dict[str, Any]] = []
    for pid, support in pid_support.items():
        if support < threshold:
            continue

        candidates = pid_items.get(pid, [])
        names = [str(x.get("process_name", "")).strip() for x in candidates if str(x.get("process_name", "")).strip()]
        reasons = [str(x.get("reason", "")).strip() for x in candidates if str(x.get("reason", "")).strip()]

        conf_values: List[float] = []
        for x in candidates:
            conf = x.get("confidence")
            if conf is None:
                continue
            try:
                conf_values.append(float(conf))
            except (TypeError, ValueError):
                continue

        process_name = Counter(names).most_common(1)[0][0] if names else ""
        reason = Counter(reasons).most_common(1)[0][0] if reasons else ""
        confidence = round(mean(conf_values), 4) if conf_values else 0.0

        merged_items.append(
            {
                "pid": pid,
                "process_name": process_name,
                "reason": reason,
                "confidence": confidence,
                "votes_for_pid": support,
            }
        )

    merged_items.sort(key=lambda x: (-x.get("votes_for_pid", 0), -x.get("confidence", 0), x.get("pid", 0)))

    return {
        "suspicious_processes": merged_items,
        "majority_vote_meta": {
            "total_runs": len(votes),
            "valid_runs": len(valid_votes),
            "threshold": threshold,
        },
    }
