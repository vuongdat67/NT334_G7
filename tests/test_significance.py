import math
import pytest
from src.evaluation.significance import mcnemar_test, build_contingency


# ---------------------------------------------------------------------------
# mcnemar_test
# ---------------------------------------------------------------------------

def test_no_discordant_pairs():
    result = mcnemar_test(0, 0)
    assert result["p_value"] == 1.0
    assert result["significant_at_05"] is False
    assert "identical" in result["interpretation"].lower()


def test_highly_significant():
    # Large imbalance → very small p-value
    result = mcnemar_test(20, 0, continuity_correction=True)
    assert result["significant_at_01"] is True
    assert result["p_value"] < 0.01


def test_not_significant_equal_counts():
    # b == c → no evidence of difference
    result = mcnemar_test(5, 5, continuity_correction=False)
    assert result["statistic"] == 0.0
    assert result["significant_at_05"] is False


def test_continuity_correction_reduces_statistic():
    result_cc = mcnemar_test(10, 2, continuity_correction=True)
    result_no = mcnemar_test(10, 2, continuity_correction=False)
    assert result_cc["statistic"] <= result_no["statistic"]


def test_negative_counts_raise():
    with pytest.raises(ValueError):
        mcnemar_test(-1, 3)


def test_chi2_boundary_values():
    # chi2 ≈ 3.8415 should give p ≈ 0.05
    # With continuity correction: (|b-c| - 1)^2 / (b+c) = 3.8415
    # Solved manually: b=15, c=2 → (15-2-1)^2 / 17 = 144/17 ≈ 8.47 (sig at 0.01)
    result = mcnemar_test(15, 2)
    assert result["significant_at_05"] is True


def test_p_value_in_range():
    result = mcnemar_test(6, 1)
    assert 0.0 <= result["p_value"] <= 1.0


# ---------------------------------------------------------------------------
# build_contingency
# ---------------------------------------------------------------------------

def test_build_contingency_basic():
    # 3 snapshots: A correct + B wrong; A wrong + B correct; both correct
    preds_a = [{1, 2}, set(), {1}]
    preds_b = [set(), {1, 2}, {1}]
    malicious = [{1, 2}, {1, 2}, {1}]
    b, c = build_contingency(preds_a, preds_b, malicious)
    assert b == 1   # snapshot 0: A correct, B wrong
    assert c == 1   # snapshot 1: A wrong, B correct


def test_build_contingency_both_wrong():
    preds_a = [set()]
    preds_b = [set()]
    malicious = [{42}]
    b, c = build_contingency(preds_a, preds_b, malicious)
    assert b == 0
    assert c == 0


def test_build_contingency_length_mismatch():
    with pytest.raises(ValueError):
        build_contingency([{1}], [{1}, {2}], [{1}])


def test_build_contingency_custom_correct_fn():
    # Custom: correct if ANY malicious PID is in pred (partial credit)
    def partial_credit(pred, mal):
        return bool(pred & mal)

    preds_a = [{1}]    # catches 1 of {1,2}
    preds_b = [set()]  # catches nothing
    malicious = [{1, 2}]
    b, c = build_contingency(preds_a, preds_b, malicious, correct_fn=partial_credit)
    assert b == 1
    assert c == 0
