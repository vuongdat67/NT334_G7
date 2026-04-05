import argparse
import ipaddress
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

from src.cli.help_format import build_standard_parser
from src.config.loader import load_json
from src.llm.client import LLMClient


def _read_wsl_windows_host_ip() -> str | None:
    resolv = "/etc/resolv.conf"
    if not os.path.exists(resolv):
        return None
    text = Path(resolv).read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^nameserver\s+(\S+)", text, re.MULTILINE)
    return m.group(1) if m else None


def _is_private_or_local_host(host: str) -> bool:
    h = host.lower()
    if h in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _default_port_for_scheme(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _build_candidate_base_urls(configured_base_url: str | None) -> list[str]:
    candidates: list[str] = []

    if configured_base_url:
        parsed = urlparse(configured_base_url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or _default_port_for_scheme(scheme)
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

        # Only add WSL-local alternatives for private/local hosts (LM Studio/Ollama).
        if _is_private_or_local_host(host):
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


def _http_probe_models(
    base_url: str,
    timeout: float,
    api_key_env: str,
) -> tuple[bool, str]:
    models_url = f"{base_url.rstrip('/')}/models"
    headers = {}
    api_key = os.getenv(api_key_env)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = Request(models_url, method="GET", headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read(300)
            preview = raw.decode("utf-8", errors="replace").replace("\n", " ")
            return True, f"HTTP {status}, preview: {preview}"
    except HTTPError as e:
        if e.code == 401 and not api_key:
            return False, f"HTTPError 401: Unauthorized (missing {api_key_env})"
        return False, f"HTTPError {e.code}: {e.reason}"
    except URLError as e:
        return False, f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return False, f"Error: {e}"


def _model_id_matches(selected_model: str, model_ids: list[str]) -> bool:
    selected = (selected_model or "").strip()
    if not selected:
        return False

    ids = {str(x).strip() for x in model_ids if str(x).strip()}
    if selected in ids:
        return True

    # Gemini often returns 'models/<id>' while user config stores bare '<id>'.
    if selected.startswith("models/"):
        bare = selected.split("models/", 1)[1]
        return bare in ids

    prefixed = f"models/{selected}"
    return prefixed in ids


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for x in items:
        s = str(x).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def main() -> int:
    load_dotenv()

    parser = build_standard_parser(
        prog="health_check.py",
        description="Preflight connectivity and model-availability check for the configured LLM provider.",
        examples=[
            "python scripts/health_check.py --config config/config.json --strict",
            "python scripts/health_check.py --config config/config.json --skip-ping",
        ],
        exit_codes={
            0: "Success",
            2: "Provider endpoint unavailable",
            3: "Selected model not found",
            4: "Ping response unexpected",
        },
    )
    parser.add_argument(
        "--config",
        default="config/config.json",
        help="Path to config JSON file",
    )
    parser.add_argument(
        "--provider",
        default="",
        choices=["", "openrouter", "gemini", "openai", "claude", "lmstudio", "ollama"],
        help="Optional provider override for this run (sets LLM_PROVIDER at runtime).",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="Optional base URL override for this run (e.g. http://192.168.30.1:1234/v1).",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Optional model override for this run (sets LLM_MODEL at runtime).",
    )
    parser.add_argument(
        "--max-models",
        type=int,
        default=30,
        help="Maximum number of model IDs to print",
    )
    parser.add_argument(
        "--skip-ping",
        action="store_true",
        help="Skip chat-completion ping and only validate endpoint/model listing.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero when endpoint/model check fails.",
    )
    args = parser.parse_args()

    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    if args.model:
        os.environ["LLM_MODEL"] = args.model

    cfg = load_json(args.config)
    if args.model:
        cfg["llm_model"] = str(args.model)
    if args.base_url:
        cfg["llm_base_url"] = str(args.base_url)

    llm_provider = str(cfg.get("llm_provider", "")).strip() or "(not-set)"
    llm_model = cfg.get("llm_model", cfg.get("openai_model", ""))
    llm_api_key_env = cfg.get("llm_api_key_env", "OPENAI_API_KEY")
    llm_base_url = cfg.get("llm_base_url")
    llm_timeout_seconds = float(cfg.get("llm_timeout_seconds", 10))

    print("== LLM Health Check ==")
    print(f"resolved_provider: {llm_provider}")
    print(f"configured_base_url: {llm_base_url}")
    print(f"selected_model: {llm_model}")
    print(f"api_key_env: {llm_api_key_env}")
    print(f"api_key_present: {'yes' if os.getenv(llm_api_key_env) else 'no'}")

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
        ok, msg = _http_probe_models(
            base,
            timeout=llm_timeout_seconds,
            api_key_env=llm_api_key_env,
        )
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
            model_ids = _dedupe_keep_order(ids)
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
        return 2 if args.strict else 0

    if not model_ids:
        print("No model ids returned by provider.")
    else:
        shown = model_ids[: max(1, args.max_models)]
        for i, model_id in enumerate(shown, start=1):
            print(f"{i}. {model_id}")
        if len(model_ids) > len(shown):
            print(f"... ({len(model_ids) - len(shown)} more not shown)")

    exact_match = _model_id_matches(str(llm_model), model_ids)
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
        if args.strict:
            return 3

    if args.skip_ping:
        print("\nPing skipped by --skip-ping.")
        print("Health check completed.")
        return 0

    print("\n[2/2] Sending tiny ping request...")
    start = time.perf_counter()
    reply = client.ping()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    ping_ok = "HEALTHY" in reply.upper()

    print(f"Ping latency: {elapsed_ms} ms")
    print(f"Ping reply: {reply}")
    print(f"Ping status: {'OK' if ping_ok else 'Unexpected format'}")
    print("\nHealth check completed.")

    if args.strict and not ping_ok:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
