import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser


def _fetch_json(url: str, timeout: float, token: str = "") -> Dict[str, Any]:
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    if token:
        headers["X-Dataverse-key"] = token

    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Invalid JSON payload from Dataverse API")
    return payload


def _fetch_dataset_files(base_url: str, doi: str, timeout: float, token: str = "") -> List[Dict[str, Any]]:
    api = (
        f"{base_url.rstrip('/')}/api/datasets/:persistentId/"
        f"?persistentId={quote(doi, safe='')}"
    )
    payload = _fetch_json(api, timeout=timeout, token=token)

    data = payload.get("data", {})
    latest = data.get("latestVersion", {})
    files = latest.get("files", [])
    if not isinstance(files, list):
        return []

    out = []
    for item in files:
        if not isinstance(item, dict):
            continue
        df = item.get("dataFile", {})
        if not isinstance(df, dict):
            continue

        file_id = df.get("id")
        filename = str(df.get("filename", ""))
        filesize = int(df.get("filesize", 0) or 0)
        content_type = str(df.get("contentType", ""))
        directory_label = str(item.get("directoryLabel", "")).strip()

        if not file_id or not filename:
            continue

        out.append(
            {
                "file_id": int(file_id),
                "filename": filename,
                "filesize": filesize,
                "content_type": content_type,
                "directory_label": directory_label,
                "download_url": f"{base_url.rstrip('/')}/api/access/datafile/{int(file_id)}",
            }
        )

    return out


def _extract_snapshot_no(name: str) -> Optional[int]:
    # Match suffix _<number>.<ext>, e.g., Snapshot_benign_100.elf
    m = re.search(r"_(\d+)\.[A-Za-z0-9]+$", name)
    if not m:
        return None
    return int(m.group(1))


def _safe_rel_path(directory_label: str, filename: str) -> Path:
    clean_name = filename.replace("\\", "_").replace("/", "_")
    if not directory_label:
        return Path(clean_name)

    clean_parts = [
        p.replace("\\", "_").replace("/", "_")
        for p in directory_label.split("/")
        if p and p.strip()
    ]
    return Path(*clean_parts) / clean_name


def _filter_files(
    rows: List[Dict[str, Any]],
    name_regex: str,
    exclude_regex: str,
    snapshot_start: int,
    snapshot_end: int,
    max_file_size_gb: float,
) -> List[Dict[str, Any]]:
    inc = re.compile(name_regex) if name_regex else None
    exc = re.compile(exclude_regex) if exclude_regex else None

    out = []
    for r in rows:
        name = str(r.get("filename", ""))
        size = int(r.get("filesize", 0) or 0)

        if inc and not inc.search(name):
            continue
        if exc and exc.search(name):
            continue

        if max_file_size_gb > 0:
            max_bytes = int(max_file_size_gb * 1024 * 1024 * 1024)
            if size > max_bytes:
                continue

        snap = _extract_snapshot_no(name)
        if snapshot_start > 0 and (snap is None or snap < snapshot_start):
            continue
        if snapshot_end > 0 and (snap is None or snap > snapshot_end):
            continue

        out.append(r)

    out.sort(
        key=lambda x: (
            _extract_snapshot_no(str(x.get("filename", ""))) is None,
            _extract_snapshot_no(str(x.get("filename", ""))) or 0,
            str(x.get("filename", "")),
        )
    )
    return out


def _download_file(url: str, dest: Path, timeout: float, token: str = "") -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_suffix(dest.suffix + ".part")

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    if token:
        headers["X-Dataverse-key"] = token

    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=timeout) as resp, temp.open("wb") as f:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)

    temp.replace(dest)


def _to_gb(size_bytes: int) -> float:
    return round(size_bytes / (1024 * 1024 * 1024), 4)


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="download_dataverse_dataset.py",
        description="Download and filter Arfeen dataset snapshots from Dataverse with resume support.",
        examples=[
            "python scripts/download_dataverse_dataset.py --doi doi:10.7910/DVN/YVL3CW --out-dir data --name-regex (?i)\\.elf$ --max-files 30 --resume",
        ],
    )
    parser.add_argument("--base-url", default="https://dataverse.harvard.edu")
    parser.add_argument("--doi", default="doi:10.7910/DVN/YVL3CW")
    parser.add_argument("--out-dir", default="data")
    parser.add_argument("--name-regex", default=r"(?i)\.elf$")
    parser.add_argument("--exclude-regex", default="")
    parser.add_argument("--snapshot-start", type=int, default=0)
    parser.add_argument("--snapshot-end", type=int, default=0)
    parser.add_argument("--max-file-size-gb", type=float, default=0.0)
    parser.add_argument("--max-files", type=int, default=0)
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    token = (os.getenv("DATAVERSE_API_TOKEN") or "").strip()

    all_files = _fetch_dataset_files(args.base_url, args.doi, timeout=args.timeout, token=token)
    filtered = _filter_files(
        all_files,
        name_regex=args.name_regex,
        exclude_regex=args.exclude_regex,
        snapshot_start=int(args.snapshot_start),
        snapshot_end=int(args.snapshot_end),
        max_file_size_gb=float(args.max_file_size_gb),
    )

    if args.max_files > 0:
        filtered = filtered[: args.max_files]

    out_dir = Path(args.out_dir)
    plan = []
    for r in filtered:
        rel_path = _safe_rel_path(str(r.get("directory_label", "")), str(r.get("filename", "")))
        dst = out_dir / rel_path

        exists_ok = False
        if args.resume and dst.exists():
            expected = int(r.get("filesize", 0) or 0)
            if expected > 0 and dst.stat().st_size == expected:
                exists_ok = True

        plan.append(
            {
                "file_id": r["file_id"],
                "filename": r["filename"],
                "filesize_bytes": int(r.get("filesize", 0) or 0),
                "filesize_gb": _to_gb(int(r.get("filesize", 0) or 0)),
                "download_url": r["download_url"],
                "output_path": str(dst),
                "skip_existing": exists_ok,
            }
        )

    total_bytes = sum(int(x["filesize_bytes"]) for x in plan)
    print(
        json.dumps(
            {
                "dataset_doi": args.doi,
                "total_files_in_dataset": len(all_files),
                "selected_files": len(plan),
                "selected_total_size_gb": _to_gb(total_bytes),
                "dry_run": bool(args.dry_run),
            },
            ensure_ascii=True,
            indent=2,
        )
    )

    if args.dry_run:
        preview = plan[: min(20, len(plan))]
        print(json.dumps({"preview": preview}, ensure_ascii=True, indent=2))
        sys.exit(0)

    downloaded = 0
    skipped = 0
    failed = 0
    failures: List[Dict[str, str]] = []

    for idx, item in enumerate(plan, start=1):
        output_path = Path(item["output_path"])

        if item["skip_existing"]:
            skipped += 1
            print(f"[{idx}/{len(plan)}] skip existing: {output_path}")
            continue

        try:
            print(f"[{idx}/{len(plan)}] downloading: {output_path}")
            _download_file(
                url=str(item["download_url"]),
                dest=output_path,
                timeout=args.timeout,
                token=token,
            )
            downloaded += 1
        except Exception as e:  # noqa: BLE001
            failed += 1
            failures.append({"output_path": str(output_path), "error": str(e)})
            print(f"[{idx}/{len(plan)}] failed: {output_path} :: {e}")

        if args.sleep_seconds > 0:
            time.sleep(args.sleep_seconds)

    print(
        json.dumps(
            {
                "selected_files": len(plan),
                "downloaded": downloaded,
                "skipped": skipped,
                "failed": failed,
                "failures": failures,
            },
            ensure_ascii=True,
            indent=2,
        )
    )
