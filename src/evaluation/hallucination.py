from typing import Any, Dict, List, Set


SYSTEM_ALLOWLIST = {
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "conhost.exe",
    "taskhostw.exe",
    "spoolsv.exe",
}


def _reason_text(item: Dict[str, Any]) -> str:
    return str(item.get("reason", "")).lower()


def analyze_hallucination_taxonomy(
    suspicious_items: List[Dict[str, Any]],
    malicious_pids: Set[int],
    process_by_pid: Dict[int, Dict[str, Any]],
) -> Dict[str, Any]:
    pred_pids: Set[int] = set()
    for x in suspicious_items:
        pid_val = x.get("pid") if isinstance(x, dict) else None
        if isinstance(pid_val, int):
            pred_pids.add(pid_val)
    fp_pids = pred_pids - malicious_pids

    type_name: List[int] = []
    type_relationship: List[int] = []
    type_cascade: List[int] = []

    for item in suspicious_items:
        if not isinstance(item, dict):
            continue
        pid = item.get("pid")
        if not isinstance(pid, int) or pid not in fp_pids:
            continue

        proc = process_by_pid.get(pid, {})
        name = str(proc.get("name", item.get("process_name", ""))).lower()
        reason = _reason_text(item)

        if name in SYSTEM_ALLOWLIST:
            type_name.append(pid)

        if any(k in reason for k in ["parent", "child", "spawn", "lineage"]):
            ppid = proc.get("ppid")
            if isinstance(ppid, int) and ppid not in malicious_pids:
                type_relationship.append(pid)

        ppid = proc.get("ppid")
        if isinstance(ppid, int) and ppid in fp_pids:
            type_cascade.append(pid)

    denom = max(1, len(pred_pids))
    return {
        "fp_total": len(fp_pids),
        "type_name_count": len(set(type_name)),
        "type_relationship_count": len(set(type_relationship)),
        "type_cascade_count": len(set(type_cascade)),
        "hallucination_rate": round(len(fp_pids) / denom, 6),
    }