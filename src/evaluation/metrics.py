import json
from typing import Any, Dict, List, Set, Tuple


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


def _compute_metrics(
    pred: Set[int],
    all_pids: Set[int],
    malicious: Set[int],
) -> Dict[str, Any]:
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


def evaluate(pred_report_path: str, labels_path: str) -> Dict[str, float]:
    """Evaluate one prediction report against one labels file."""
    pred = _to_pid_set(pred_report_path)
    all_pids, malicious = _labels_to_sets(labels_path)
    return _compute_metrics(pred, all_pids, malicious)


def evaluate_multi(
    family_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Aggregate per-family metrics and compute macro-averages (Precision, Recall, F1).

    Args:
        family_results: list of dicts, each with:
            - "family"           (str)  ransomware family name
            - "pred_report_path" (str)  path to triage_report.json
            - "labels_path"      (str)  path to labels JSON

    Returns:
        {
          "per_family": { family: {tp, fp, fn, tn, accuracy, precision, recall, f1, ...} },
          "macro_precision": float,
          "macro_recall":    float,
          "macro_f1":        float,
          "micro_precision": float,   # pooled TP/(TP+FP) across all families
          "micro_recall":    float,
          "micro_f1":        float,
        }

    Macro-F1 is the arithmetic mean of per-family F1 scores (each family weighted equally),
    consistent with the comparison convention used in related ML baselines (Arfeen et al. 2022).
    Micro-F1 uses pooled counts — it gives higher weight to larger families.
    """
    per_family: Dict[str, Dict[str, Any]] = {}

    def _recompute_from_counts(counts: Dict[str, int]) -> Dict[str, Any]:
        tp = int(counts.get("tp", 0))
        fp = int(counts.get("fp", 0))
        fn = int(counts.get("fn", 0))
        tn = int(counts.get("tn", 0))
        total = tp + fp + fn + tn

        accuracy = (tp + tn) / total if total else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        triage_efficiency = tp / (tp + fp) if (tp + fp) else 0.0

        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "accuracy": round(accuracy, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "triage_efficiency": round(triage_efficiency, 6),
        }

    total_tp = total_fp = total_fn = total_tn = 0

    for entry in family_results:
        family = str(entry.get("family", "unknown"))
        pred = _to_pid_set(entry["pred_report_path"])
        all_pids, malicious = _labels_to_sets(entry["labels_path"])
        m = _compute_metrics(pred, all_pids, malicious)

        if family not in per_family:
            per_family[family] = {
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "tn": 0,
            }
        per_family[family]["tp"] += int(m["tp"])
        per_family[family]["fp"] += int(m["fp"])
        per_family[family]["fn"] += int(m["fn"])
        per_family[family]["tn"] += int(m["tn"])

        total_tp += m["tp"]
        total_fp += m["fp"]
        total_fn += m["fn"]
        total_tn += m["tn"]

    for family, counts in list(per_family.items()):
        per_family[family] = _recompute_from_counts(counts)

    n = len(per_family)
    if n == 0:
        return {"per_family": {}, "macro_precision": 0.0, "macro_recall": 0.0, "macro_f1": 0.0,
                "micro_precision": 0.0, "micro_recall": 0.0, "micro_f1": 0.0}

    macro_precision = sum(m["precision"] for m in per_family.values()) / n
    macro_recall = sum(m["recall"] for m in per_family.values()) / n
    macro_f1 = sum(m["f1"] for m in per_family.values()) / n

    micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    micro_f1 = (
        2 * micro_precision * micro_recall / (micro_precision + micro_recall)
        if (micro_precision + micro_recall)
        else 0.0
    )

    return {
        "per_family": per_family,
        "macro_precision": round(macro_precision, 6),
        "macro_recall": round(macro_recall, 6),
        "macro_f1": round(macro_f1, 6),
        "micro_precision": round(micro_precision, 6),
        "micro_recall": round(micro_recall, 6),
        "micro_f1": round(micro_f1, 6),
    }


def consistency_score(votes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Measure per-run agreement across majority_runs to quantify LLM stability.

    Args:
        votes: list of individual run outputs from pipeline (each triage_once() result),
               i.e. the contents of triage_votes.json.

    Returns:
        {
          "total_runs":      int,
          "valid_runs":      int,
          "unique_pid_sets": int,   # how many distinct PID-sets appeared across runs
          "perfect_agreement": bool,  # all valid runs returned the same PID set
          "mean_agreement_rate": float,  # fraction of runs that agree with the majority-vote set
          "per_pid_support": { pid: support_count },  # how many runs flagged each PID
        }

    A perfect_agreement=True means temperature=0 produced fully deterministic output
    (desirable). Low mean_agreement_rate indicates high LLM variance for this prompt.
    """
    valid_votes = [v for v in votes if isinstance(v, dict) and not v.get("api_error")]
    if not valid_votes:
        return {
            "total_runs": len(votes),
            "valid_runs": 0,
            "unique_pid_sets": 0,
            "perfect_agreement": False,
            "mean_agreement_rate": 0.0,
            "per_pid_support": {},
        }

    # Build per-run PID sets.
    pid_sets: List[frozenset] = []
    pid_support: Dict[int, int] = {}
    for vote in valid_votes:
        items = vote.get("suspicious_processes", [])
        run_pids: Set[int] = set()
        for item in items:
            if isinstance(item, dict):
                pid = item.get("pid")
                if isinstance(pid, int):
                    run_pids.add(pid)
        pid_sets.append(frozenset(run_pids))
        for pid in run_pids:
            pid_support[pid] = pid_support.get(pid, 0) + 1

    unique_sets = len(set(pid_sets))
    perfect_agreement = unique_sets == 1

    # Majority-vote PID set: PIDs that appear in more than half the valid runs.
    threshold = (len(valid_votes) // 2) + 1
    majority_pids = frozenset(pid for pid, cnt in pid_support.items() if cnt >= threshold)

    # Agreement rate: for each run, fraction of its PIDs that match the majority set
    # (Jaccard similarity between run PID set and majority set).
    agreement_rates = []
    for run_pids in pid_sets:
        union = run_pids | majority_pids
        if not union:
            agreement_rates.append(1.0)
            continue
        intersection = run_pids & majority_pids
        agreement_rates.append(len(intersection) / len(union))

    mean_agreement = sum(agreement_rates) / len(agreement_rates) if agreement_rates else 0.0

    return {
        "total_runs": len(votes),
        "valid_runs": len(valid_votes),
        "unique_pid_sets": unique_sets,
        "perfect_agreement": perfect_agreement,
        "mean_agreement_rate": round(mean_agreement, 6),
        "per_pid_support": {str(pid): cnt for pid, cnt in sorted(pid_support.items())},
    }
