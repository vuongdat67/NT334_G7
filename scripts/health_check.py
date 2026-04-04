import argparse
import os
import re
import sys
import time
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config_loader import load_json
from src.llm_client import LLMClient


def _read_wsl_windows_host_ip() -> str | None:
    resolv = "/etc/resolv.conf"
    if not os.path.exists(resolv):
        return None
    text = Path(resolv).read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^nameserver\s+(\S+)", text, re.MULTILINE)
    return m.group(1) if m else None


def _build_candidate_base_urls(configured_base_url: str | None) -> list[str]:
    candidates: list[str] = []

    if configured_base_url:
        parsed = urlparse(configured_base_url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 1234
        path = parsed.path.rstrip("/")

        paths = []
        if path in {"/v1", "/api/v1"}:
            paths.append(path)
        elif path:
            paths.extend([path, "/v1", "/api/v1"])
        else:
            paths.extend(["/v1", "/api/v1"])

        for p in paths:
            candidates.append(f"{scheme}://{host}:{port}{p}")

        # WSL often reaches Windows-hosted services via localhost or the nameserver IP.
        for alt_host in ["localhost", "127.0.0.1", _read_wsl_windows_host_ip()]:
            if alt_host and alt_host != host:
                for p in paths:
                    candidates.append(f"{scheme}://{alt_host}:{port}{p}")
    else:
        host_ip = _read_wsl_windows_host_ip()
        for host in ["localhost", "127.0.0.1", host_ip]:
            if host:
                candidates.append(f"http://{host}:1234/v1")
                candidates.append(f"http://{host}:1234/api/v1")

    # De-duplicate while preserving order.
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _http_probe_models(base_url: str, timeout: float) -> tuple[bool, str]:
    models_url = f"{base_url.rstrip('/')}/models"
    req = Request(models_url, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read(300)
            preview = raw.decode("utf-8", errors="replace").replace("\n", " ")
            return True, f"HTTP {status}, preview: {preview}"
    except HTTPError as e:
        return False, f"HTTPError {e.code}: {e.reason}"
    except URLError as e:
        return False, f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return False, f"Error: {e}"


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="config/config.local.json",
        help="Path to config JSON file",
    )
    args = parser.parse_args()

    cfg = load_json(args.config)
    llm_model = cfg.get("llm_model", cfg.get("openai_model", ""))
    llm_api_key_env = cfg.get("llm_api_key_env", "OPENAI_API_KEY")
    llm_base_url = cfg.get("llm_base_url")
    llm_timeout_seconds = float(cfg.get("llm_timeout_seconds", 10))

    print("== LLM Health Check ==")
    print(f"configured_base_url: {llm_base_url}")
    print(f"selected_model: {llm_model}")
    print(f"api_key_env: {llm_api_key_env}")

    candidates = _build_candidate_base_urls(llm_base_url)
    print("\nCandidate base URLs:")
    for c in candidates:
        print(f"- {c}")

    print("\n[1/2] Fetching model list...")
    client = None
    model_ids = []
    errors: list[tuple[str, str]] = []

    for base in candidates:
        print(f"Trying: {base}")
        ok, msg = _http_probe_models(base, timeout=llm_timeout_seconds)
        print(f"  Probe: {msg}")
        if not ok:
            errors.append((base, msg))
            continue
        try:
            trial = LLMClient(
                model=llm_model,
                temperature=0,
                api_key_env=llm_api_key_env,
                base_url=base,
                timeout_seconds=llm_timeout_seconds,
            )
            ids = trial.list_model_ids()
            client = trial
            model_ids = ids
            print(f"Connected: {base}")
            break
        except Exception as e:  # noqa: BLE001
            errors.append((base, str(e)))

    if client is None:
        print("Could not connect to any candidate endpoint.")
        print("Errors:")
        for base, err in errors:
            print(f"- {base}: {err}")
        print("\nTips:")
        print("1) Ensure LM Studio server is running on host and same port.")
        print("2) If using WSL, test localhost and /api/v1 as alternatives.")
        print("3) On Windows firewall, allow inbound for LM Studio server port 1234.")
        return

    if not model_ids:
        print("No model ids returned by provider.")
    else:
        for i, model_id in enumerate(model_ids, start=1):
            print(f"{i}. {model_id}")

    exact_match = llm_model in model_ids
    if exact_match:
        print("\nModel match: OK (selected model id exists)")
    else:
        print("\nModel match: NOT FOUND")
        lower = llm_model.lower()
        suggestions = [m for m in model_ids if lower in m.lower() or m.lower() in lower]
        if suggestions:
            print("Closest ids:")
            for m in suggestions[:5]:
                print(f"- {m}")

    print("\n[2/2] Sending tiny ping request...")
    start = time.perf_counter()
    reply = client.ping()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    ping_ok = "HEALTHY" in reply.upper()

    print(f"Ping latency: {elapsed_ms} ms")
    print(f"Ping reply: {reply}")
    print(f"Ping status: {'OK' if ping_ok else 'Unexpected format'}")
    print("\nHealth check completed.")


if __name__ == "__main__":
    main()
