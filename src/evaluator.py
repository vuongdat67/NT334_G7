import json
from typing import Dict, Set, Tuple


def _to_pid_set(report_path: str) -> Set[int]:
    data = json.loads(open(report_path, "r", encoding="utf-8").read())
    items = data.get("suspicious_processes", [])
    pids = set()
    for item in items:
        pid = item.get("pid")
        if isinstance(pid, int):
            pids.add(pid)
    return pids


def _labels_to_sets(labels_path: str) -> Tuple[Set[int], Set[int]]:
    data = json.loads(open(labels_path, "r", encoding="utf-8").read())
    all_pids = set(data.get("all_pids", []))
    malicious_pids = set(data.get("malicious_pids", []))
    return all_pids, malicious_pids


def evaluate(pred_report_path: str, labels_path: str) -> Dict[str, float]:
    pred = _to_pid_set(pred_report_path)
    all_pids, malicious = _labels_to_sets(labels_path)

    benign = all_pids - malicious

    tp = len(pred & malicious)
    fp = len(pred & benign)
    fn = len((all_pids - pred) & malicious)
    tn = len((all_pids - pred) & benign)

    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    triage_efficiency = (tp + fp) / total if total else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "triage_efficiency": triage_efficiency,
    }
