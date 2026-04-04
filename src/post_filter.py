import re
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_SYSTEM_ALLOWLIST = {
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "svchost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "explorer.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "wermgr.exe",
    "sihost.exe",
    "ctfmon.exe",
}

DEFAULT_PARENT_SANITY = {
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe", "winlogon.exe"},
    "svchost.exe": {"services.exe"},
    "dwm.exe": {"winlogon.exe"},
    "fontdrvhost.exe": {"wininit.exe", "winlogon.exe"},
    "spoolsv.exe": {"services.exe"},
    "explorer.exe": {"userinit.exe", "winlogon.exe"},
    "conhost.exe": {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "python.exe",
        "explorer.exe",
    },
}

DEFAULT_STRONG_REASON_KEYWORDS = {
    "shellcode",
    "inject",
    "injection",
    "malfind",
    "page_execute_readwrite",
    "execute_readwrite",
    "rwx",
    "mz",
    "pe header",
}

DEFAULT_GENERIC_REASON_KEYWORDS = {
    "unusual parent-child",
    "file output is disabled",
    "offset",
    "suspicious",
    "not enough information",
    "uncertain",
    "generic",
}


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _find_value(row: Dict[str, Any], candidates: List[str]) -> Any:
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
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _extract_pslist_rows(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    ps = artifacts.get("windows.pslist")
    if isinstance(ps, list):
        return [x for x in ps if isinstance(x, dict)]
    if isinstance(ps, dict):
        rows = ps.get("rows")
        if isinstance(rows, list):
            return [x for x in rows if isinstance(x, dict)]
    return []


def _index_processes(pslist_rows: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    by_pid: Dict[int, Dict[str, Any]] = {}
    for row in pslist_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        if pid is None:
            continue
        ppid = _to_int(_find_value(row, ["ppid", "parentpid", "inheritedfromuniqueprocessid"]))
        name = _find_value(row, ["imagefilename", "processname", "name", "imagename"])
        name_text = str(name).strip().lower() if name is not None else ""
        by_pid[pid] = {
            "pid": pid,
            "ppid": ppid,
            "name": name_text,
            "raw": row,
        }
    return by_pid


def _contains_any(text: str, keywords: set[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def apply_conservative_post_filter(
    report: Dict[str, Any],
    artifacts: Dict[str, Any],
    cfg: Dict[str, Any],
) -> Dict[str, Any]:
    output = deepcopy(report)
    input_items = output.get("suspicious_processes", [])
    if not isinstance(input_items, list):
        input_items = []

    allowlist = {x.lower() for x in cfg.get("post_filter_system_allowlist", DEFAULT_SYSTEM_ALLOWLIST)}
    parent_sanity_cfg = cfg.get("post_filter_parent_sanity", DEFAULT_PARENT_SANITY)
    parent_sanity = {
        str(k).lower(): {str(v).lower() for v in values}
        for k, values in parent_sanity_cfg.items()
    }

    strong_keywords = {
        str(x).lower()
        for x in cfg.get("post_filter_strong_reason_keywords", DEFAULT_STRONG_REASON_KEYWORDS)
    }
    generic_keywords = {
        str(x).lower()
        for x in cfg.get("post_filter_generic_reason_keywords", DEFAULT_GENERIC_REASON_KEYWORDS)
    }
    min_conf_keep = float(cfg.get("post_filter_min_conf_keep_for_allowlisted", 0.9))

    ps_rows = _extract_pslist_rows(artifacts)
    by_pid = _index_processes(ps_rows)

    kept: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []

    for item in input_items:
        if not isinstance(item, dict):
            continue

        pid = _to_int(item.get("pid"))
        reason = str(item.get("reason", ""))
        confidence = item.get("confidence", 0)
        try:
            confidence_f = float(confidence)
        except (TypeError, ValueError):
            confidence_f = 0.0

        item_name = str(item.get("process_name", "")).strip().lower()
        observed = by_pid.get(pid) if pid is not None else None
        observed_name = observed.get("name", "") if observed else ""
        process_name = item_name or observed_name

        ppid = observed.get("ppid") if observed else None
        parent_name = by_pid.get(ppid, {}).get("name", "") if ppid is not None else ""

        is_allowlisted = process_name in allowlist
        has_strong_signal = _contains_any(reason, strong_keywords)
        has_generic_reason = _contains_any(reason, generic_keywords)

        parent_is_sane = False
        expected_parents = parent_sanity.get(process_name)
        if expected_parents and parent_name:
            parent_is_sane = parent_name in expected_parents

        drop_rule = None
        if is_allowlisted and parent_is_sane and not has_strong_signal:
            drop_rule = "allowlisted_process_with_sane_parent"
        elif is_allowlisted and (confidence_f < min_conf_keep) and not has_strong_signal and has_generic_reason:
            drop_rule = "allowlisted_low_confidence_generic_reason"
        elif is_allowlisted and pid is not None and pid not in by_pid and not has_strong_signal:
            drop_rule = "allowlisted_pid_not_in_pslist"

        if drop_rule:
            dropped.append(
                {
                    "pid": pid,
                    "process_name": process_name,
                    "reason": reason,
                    "confidence": confidence_f,
                    "parent_name": parent_name,
                    "rule": drop_rule,
                }
            )
            continue

        kept.append(item)

    output["suspicious_processes"] = kept
    output["post_filter"] = {
        "enabled": True,
        "input_count": len(input_items),
        "kept_count": len(kept),
        "dropped_count": len(dropped),
        "dropped_items": dropped,
    }
    return output
