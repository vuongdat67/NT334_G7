import json
import os
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict


def _expand_env_in_value(value):
    if isinstance(value, str):
        expanded = os.path.expandvars(value)
        expanded = os.path.expanduser(expanded)
        return expanded
    if isinstance(value, list):
        return [_expand_env_in_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env_in_value(v) for k, v in value.items()}
    return value


def _env_text(name: str) -> str:
    return (os.getenv(name) or "").strip()


def _detect_provider_candidates_from_env() -> list[str]:
    candidates: list[str] = []
    if _env_text("OPENROUTER_API_KEY"):
        candidates.append("openrouter")
    if _env_text("GEMINI_API_KEY"):
        candidates.append("gemini")
    if _env_text("OPENAI_API_KEY"):
        candidates.append("openai")
    return candidates


def _load_provider_profiles(path: str) -> Dict[str, Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Provider profiles file not found: {path}. "
            "Create config/provider_profiles.json or set PROVIDER_PROFILES_PATH."
        )
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Provider profiles must be a JSON object")
    return {str(k).strip().lower(): v for k, v in data.items() if isinstance(v, dict)}


def _apply_provider_profile(data: dict) -> None:
    provider = str(data.get("llm_provider") or _env_text("LLM_PROVIDER")).strip().lower()
    if not provider:
        # Convenience fallback for quick setup when user provides exactly one API key in .env.
        inferred = _detect_provider_candidates_from_env()
        if len(inferred) == 1:
            provider = inferred[0]
        elif len(inferred) > 1:
            raise ValueError(
                "Multiple provider API keys are present in .env but LLM_PROVIDER is empty. "
                f"Detected: {', '.join(inferred)}. Set LLM_PROVIDER explicitly."
            )
    if not provider:
        return

    profiles_path = str(
        data.get("provider_profiles_path")
        or _env_text("PROVIDER_PROFILES_PATH")
        or "config/provider_profiles.json"
    ).strip()
    profiles = _load_provider_profiles(profiles_path)
    if provider not in profiles:
        available = ", ".join(sorted(profiles.keys()))
        raise ValueError(
            f"Unknown llm_provider: {provider}. Available providers: {available}"
        )

    profile = profiles[provider]
    data["llm_provider"] = provider
    data.setdefault("provider_profiles_path", profiles_path)

    if not data.get("llm_base_url") and profile.get("llm_base_url"):
        data["llm_base_url"] = str(profile.get("llm_base_url"))
    if not data.get("llm_api_key_env") and profile.get("llm_api_key_env"):
        data["llm_api_key_env"] = str(profile.get("llm_api_key_env"))

    if not data.get("llm_model"):
        model_env = str(profile.get("llm_model_env", "")).strip()
        if model_env and _env_text(model_env):
            data["llm_model"] = _env_text(model_env)
        elif profile.get("llm_model"):
            data["llm_model"] = str(profile.get("llm_model"))
        elif _env_text("LLM_MODEL"):
            data["llm_model"] = _env_text("LLM_MODEL")


def _is_local_base_url(base_url: str) -> bool:
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


def load_json(path: str) -> dict:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    data = _expand_env_in_value(data)
    if not isinstance(data, dict):
        raise ValueError(f"Config JSON must be an object: {path}")

    # Allow optional env defaulting for commonly switched fields.
    if isinstance(data, dict):
        _apply_provider_profile(data)

        if not data.get("memory_dump_path"):
            memory_dump_file = _env_text("MEMORY_DUMP_FILE")
            memory_dump_folder = _env_text("MEMORY_DUMP_FOLDER")

            if memory_dump_file:
                data["memory_dump_path"] = memory_dump_file
            elif memory_dump_folder:
                folder = Path(memory_dump_folder)
                if folder.exists():
                    candidates = sorted(folder.rglob("*.elf"))
                    if candidates:
                        data["memory_dump_path"] = str(candidates[0])

        if not data.get("llm_model") and os.getenv("LLM_MODEL"):
            data["llm_model"] = _env_text("LLM_MODEL")
        if not data.get("llm_base_url"):
            llm_base_url = _env_text("LLM_BASE_URL")
            openai_base_url = _env_text("OPENAI_BASE_URL")
            if llm_base_url:
                data["llm_base_url"] = llm_base_url
            elif openai_base_url:
                data["llm_base_url"] = openai_base_url

        if not data.get("llm_api_key_env"):
            llm_api_key_env = _env_text("LLM_API_KEY_ENV")
            base_url = str(data.get("llm_base_url", ""))

            if llm_api_key_env:
                data["llm_api_key_env"] = llm_api_key_env
            elif "openrouter" in base_url and _env_text("OPENROUTER_API_KEY"):
                data["llm_api_key_env"] = "OPENROUTER_API_KEY"
            elif "generativelanguage.googleapis.com" in base_url and _env_text("GEMINI_API_KEY"):
                data["llm_api_key_env"] = "GEMINI_API_KEY"
            elif _is_local_base_url(base_url):
                data["llm_api_key_env"] = "LOCAL_LLM_API_KEY"
            elif _env_text("OPENAI_API_KEY"):
                data["llm_api_key_env"] = "OPENAI_API_KEY"
            else:
                data["llm_api_key_env"] = "OPENAI_API_KEY"

    return data
