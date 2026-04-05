import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _find_value(row: Dict[str, Any], candidates: Iterable[str]) -> Any:
    if not isinstance(row, dict):
        return None
    normalized_candidates = {_normalize_key(c) for c in candidates}
    for key, value in row.items():
        if _normalize_key(key) in normalized_candidates:
            return value
    return None


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _extract_rows(block: Any) -> List[Dict[str, Any]]:
    if isinstance(block, list):
        return [x for x in block if isinstance(x, dict)]
    if isinstance(block, dict):
        rows = block.get("rows")
        if isinstance(rows, list):
            return [x for x in rows if isinstance(x, dict)]
    return []


def _looks_random_name(name: str) -> bool:
    n = (name or "").lower().strip()
    if len(n) < 8:
        return False
    if n.endswith(".exe"):
        n = n[:-4]

    if re.fullmatch(r"[0-9a-f]{8,}", n):
        return True
    if re.fullmatch(r"[a-z0-9]{8,}", n) and sum(ch.isdigit() for ch in n) >= 2:
        # A conservative random-like heuristic.
        vowels = sum(ch in "aeiou" for ch in n)
        return vowels <= max(1, len(n) // 6)
    return False


def run_rule_baseline(
    artifacts: Dict[str, Any],
    known_malicious_names: Iterable[str],
) -> Dict[str, Any]:
    known_set = {str(x).lower().strip() for x in known_malicious_names if str(x).strip()}

    ps_rows = _extract_rows(artifacts.get("windows.pslist"))
    vad_rows = _extract_rows(artifacts.get("windows.vadinfo"))
    mal_rows = _extract_rows(artifacts.get("windows.malfind"))

    pid_info: Dict[int, Dict[str, Any]] = {}
    signals: Dict[int, Set[str]] = defaultdict(set)

    for row in ps_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        name = str(_find_value(row, ["imagefilename", "processname", "name", "imagename"]) or "").strip()
        if pid is None:
            continue
        pid_info[pid] = {"name": name}

        name_l = name.lower()
        if name_l in known_set or name_l[:15] in known_set:
            signals[pid].add("known_malicious_name")
        if _looks_random_name(name):
            signals[pid].add("random_like_name")

    for row in vad_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        if pid is None:
            continue
        prot = str(_find_value(row, ["protection", "protectionstring", "protect"]) or "").lower()
        if "execute" in prot and "write" in prot:
            signals[pid].add("rwx_vad")

    for row in mal_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        if pid is None:
            continue

        text_blob = " ".join(str(v) for v in row.values()).lower()
        if "mz" in text_blob:
            signals[pid].add("malfind_mz")
        if any(k in text_blob for k in ["shellcode", "pushad", "jmp", "call"]):
            signals[pid].add("malfind_shellcode")

    suspicious_items = []
    for pid, pid_signals in signals.items():
        if len(pid_signals) == 0:
            continue

        score = 0.0
        if "known_malicious_name" in pid_signals:
            score += 0.5
        if "random_like_name" in pid_signals:
            score += 0.3
        if "rwx_vad" in pid_signals:
            score += 0.3
        if "malfind_mz" in pid_signals:
            score += 0.2
        if "malfind_shellcode" in pid_signals:
            score += 0.2
        confidence = min(1.0, round(score, 4))

        suspicious_items.append(
            {
                "pid": pid,
                "process_name": pid_info.get(pid, {}).get("name", ""),
                "reason": "rule_signals=" + ",".join(sorted(pid_signals)),
                "confidence": confidence,
            }
        )

    suspicious_items.sort(key=lambda x: (-x.get("confidence", 0), x.get("pid", 0)))
    return {
        "suspicious_processes": suspicious_items,
        "baseline": "rule_v1",
    }