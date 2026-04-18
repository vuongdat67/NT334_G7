"""
Statistical significance testing for paired LLM model comparison.

McNemar's test is the standard choice when comparing two classifiers on the
same evaluation set (matched pairs). It is especially important here because
some families have very few snapshots (TeslaCrypt: n=13), where standard
chi-square or t-tests are unreliable.

Typical usage:

    from src.evaluation.significance import mcnemar_test, build_contingency

    # Build contingency from per-snapshot recall results:
    n_b, n_c = build_contingency(recalls_model_a, recalls_model_b, threshold=1.0)
    result = mcnemar_test(n_b, n_c)
    print(result["interpretation"])

Reference:
    McNemar, Q. (1947). Note on the sampling error of the difference between
    correlated proportions or percentages. Psychometrika, 12(2), 153–157.
"""
import math
from typing import Any, Dict, List, Tuple


# ---------------------------------------------------------------------------
# Chi-square survival function (df=1) using only stdlib math.
# P(chi2 > x | df=1) = erfc(sqrt(x/2))
# Verified: P(chi2 > 3.8415) ≈ 0.05, P(chi2 > 6.6349) ≈ 0.01
# ---------------------------------------------------------------------------

def _chi2_sf_df1(x: float) -> float:
    """Survival function of chi-squared distribution with df=1 (stdlib only)."""
    if x <= 0.0:
        return 1.0
    return math.erfc(math.sqrt(x / 2.0))


# ---------------------------------------------------------------------------
# Core McNemar test
# ---------------------------------------------------------------------------

def mcnemar_test(
    n_correct_a_wrong_b: int,
    n_wrong_a_correct_b: int,
    continuity_correction: bool = True,
) -> Dict[str, Any]:
    """
    McNemar's test for two paired classifiers evaluated on the same samples.

    Given matched-pair outcomes, only the *discordant* cells matter:
      b = n_correct_a_wrong_b : model A correct, model B wrong
      c = n_wrong_a_correct_b : model A wrong, model B correct

    H0: P(A correct, B wrong) == P(A wrong, B correct), i.e. equal error rates.

    Args:
        n_correct_a_wrong_b: off-diagonal count b
        n_wrong_a_correct_b: off-diagonal count c
        continuity_correction: apply Edwards' continuity correction (recommended
            when b+c < 25 — common with small forensics datasets).

    Returns:
        {
          "b": int,
          "c": int,
          "statistic": float,        # chi-square statistic
          "p_value": float,          # two-tailed p-value
          "significant_at_05": bool,
          "significant_at_01": bool,
          "interpretation": str,
        }
    """
    b = int(n_correct_a_wrong_b)
    c = int(n_wrong_a_correct_b)

    if b < 0 or c < 0:
        raise ValueError("Contingency counts must be non-negative.")

    if b + c == 0:
        return {
            "b": b,
            "c": c,
            "statistic": 0.0,
            "p_value": 1.0,
            "significant_at_05": False,
            "significant_at_01": False,
            "interpretation": "No discordant pairs — models produce identical outputs on every sample.",
        }

    if continuity_correction:
        # Edwards' continuity correction: subtract 1 from |b-c| before squaring.
        numerator = max(0.0, abs(b - c) - 1.0) ** 2
    else:
        numerator = float((b - c) ** 2)

    statistic = numerator / (b + c)
    p_value = _chi2_sf_df1(statistic)

    sig_05 = p_value < 0.05
    sig_01 = p_value < 0.01

    if sig_01:
        interp = f"Highly significant (p={p_value:.4f} < 0.01): models differ substantially."
    elif sig_05:
        interp = f"Significant (p={p_value:.4f} < 0.05): models differ."
    else:
        interp = f"Not significant (p={p_value:.4f} >= 0.05): no evidence models differ."

    return {
        "b": b,
        "c": c,
        "statistic": round(statistic, 6),
        "p_value": round(p_value, 6),
        "significant_at_05": sig_05,
        "significant_at_01": sig_01,
        "interpretation": interp,
    }


# ---------------------------------------------------------------------------
# Contingency builder from per-snapshot prediction sets
# ---------------------------------------------------------------------------

def build_contingency(
    preds_a: List[set],
    preds_b: List[set],
    malicious_sets: List[set],
    correct_fn=None,
) -> Tuple[int, int]:
    """
    Build the discordant counts (b, c) for McNemar's test from snapshot predictions.

    A snapshot is "correctly triaged" if the prediction set has zero false negatives
    (recall == 1.0): all malicious PIDs were flagged. This is the primary goal of
    triage — missing a malicious process is worse than a false positive.

    Args:
        preds_a:       list of predicted-PID sets from model A (one per snapshot)
        preds_b:       list of predicted-PID sets from model B (one per snapshot)
        malicious_sets: list of true malicious-PID sets (one per snapshot, same order)
        correct_fn:    optional callable(pred_set, malicious_set) → bool.
                       Defaults to zero-FN (perfect recall) criterion.

    Returns:
        (b, c) where:
          b = count of snapshots where A correct and B wrong
          c = count of snapshots where A wrong and B correct
    """
    if len(preds_a) != len(preds_b) or len(preds_a) != len(malicious_sets):
        raise ValueError("preds_a, preds_b, and malicious_sets must have the same length.")

    if correct_fn is None:
        def correct_fn(pred: set, mal: set) -> bool:  # type: ignore[misc]
            # Correct = no false negatives (all malicious PIDs flagged).
            return mal.issubset(pred)

    b = c = 0
    for pred_a, pred_b, mal in zip(preds_a, preds_b, malicious_sets):
        ok_a = correct_fn(pred_a, mal)
        ok_b = correct_fn(pred_b, mal)
        if ok_a and not ok_b:
            b += 1
        elif not ok_a and ok_b:
            c += 1

    return b, c
