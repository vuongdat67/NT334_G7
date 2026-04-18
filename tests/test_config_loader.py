import json
from pathlib import Path

from src.config.loader import load_json


def test_load_json_inferrs_provider_from_openrouter_key(tmp_path, monkeypatch):
    profiles = {
        "openrouter": {
            "llm_base_url": "https://openrouter.ai/api/v1",
            "llm_api_key_env": "OPENROUTER_API_KEY",
            "llm_model": "qwen/qwen3.6-plus:free",
        }
    }
    profiles_path = tmp_path / "provider_profiles.json"
    profiles_path.write_text(json.dumps(profiles), encoding="utf-8")

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "llm_provider": "",
                "provider_profiles_path": str(profiles_path),
                "llm_model": "",
                "llm_base_url": "",
                "llm_api_key_env": "",
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    data = load_json(str(cfg_path))

    assert data["llm_provider"] == "openrouter"
    assert data["llm_base_url"] == "https://openrouter.ai/api/v1"
    assert data["llm_api_key_env"] == "OPENROUTER_API_KEY"


def test_load_json_raises_when_multiple_provider_keys_and_no_selector(tmp_path, monkeypatch):
    profiles = {
        "openrouter": {
            "llm_base_url": "https://openrouter.ai/api/v1",
            "llm_api_key_env": "OPENROUTER_API_KEY",
            "llm_model": "qwen/qwen3.6-plus:free",
        },
        "gemini": {
            "llm_base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
            "llm_api_key_env": "GEMINI_API_KEY",
            "llm_model": "gemini-2.0-flash",
        },
    }
    profiles_path = tmp_path / "provider_profiles.json"
    profiles_path.write_text(json.dumps(profiles), encoding="utf-8")

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "llm_provider": "",
                "provider_profiles_path": str(profiles_path),
                "llm_model": "",
                "llm_base_url": "",
                "llm_api_key_env": "",
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy-or")
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-gm")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    try:
        load_json(str(cfg_path))
        raise AssertionError("Expected ValueError for ambiguous provider keys")
    except ValueError as e:
        assert "Multiple provider API keys" in str(e)


def test_load_json_inferrs_provider_from_nvidia_key(tmp_path, monkeypatch):
    profiles = {
        "nvidia": {
            "llm_base_url": "https://integrate.api.nvidia.com/v1",
            "llm_api_key_env": "NVIDIA_API_KEY",
            "llm_model": "minimaxai/minimax-m2.7",
        }
    }
    profiles_path = tmp_path / "provider_profiles.json"
    profiles_path.write_text(json.dumps(profiles), encoding="utf-8")

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "llm_provider": "",
                "provider_profiles_path": str(profiles_path),
                "llm_model": "",
                "llm_base_url": "",
                "llm_api_key_env": "",
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("NVIDIA_API_KEY", "dummy-nv")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    data = load_json(str(cfg_path))

    assert data["llm_provider"] == "nvidia"
    assert data["llm_base_url"] == "https://integrate.api.nvidia.com/v1"
    assert data["llm_api_key_env"] == "NVIDIA_API_KEY"
