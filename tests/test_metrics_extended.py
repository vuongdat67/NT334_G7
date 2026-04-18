from src.evaluation.metrics import consistency_score, evaluate_multi


def test_evaluate_multi_macro_f1(tmp_path):
    # Family A: perfect prediction
    pred_a = tmp_path / "pred_a.json"
    labels_a = tmp_path / "labels_a.json"
    pred_a.write_text('{"suspicious_processes": [{"pid": 1}]}', encoding="utf-8")
    labels_a.write_text('{"all_pids": [1, 2], "malicious_pids": [1]}', encoding="utf-8")

    # Family B: no true positives
    pred_b = tmp_path / "pred_b.json"
    labels_b = tmp_path / "labels_b.json"
    pred_b.write_text('{"suspicious_processes": []}', encoding="utf-8")
    labels_b.write_text('{"all_pids": [3, 4], "malicious_pids": [3]}', encoding="utf-8")

    result = evaluate_multi([
        {"family": "A", "pred_report_path": str(pred_a), "labels_path": str(labels_a)},
        {"family": "B", "pred_report_path": str(pred_b), "labels_path": str(labels_b)},
    ])

    assert "per_family" in result
    assert "A" in result["per_family"]
    assert "B" in result["per_family"]
    assert result["per_family"]["A"]["tp"] == 1
    assert result["per_family"]["B"]["fn"] == 1
    # Macro F1 = mean of (1.0, 0.0) = 0.5
    assert abs(result["macro_f1"] - 0.5) < 1e-6
    assert 0.0 <= result["micro_f1"] <= 1.0


def test_evaluate_multi_empty():
    result = evaluate_multi([])
    assert result["macro_f1"] == 0.0
    assert result["per_family"] == {}


def test_evaluate_multi_aggregates_same_family(tmp_path):
    pred_1 = tmp_path / "pred_1.json"
    labels_1 = tmp_path / "labels_1.json"
    pred_1.write_text('{"suspicious_processes": [{"pid": 1}]}', encoding="utf-8")
    labels_1.write_text('{"all_pids": [1, 2], "malicious_pids": [1]}', encoding="utf-8")

    pred_2 = tmp_path / "pred_2.json"
    labels_2 = tmp_path / "labels_2.json"
    pred_2.write_text('{"suspicious_processes": []}', encoding="utf-8")
    labels_2.write_text('{"all_pids": [3, 4], "malicious_pids": [3]}', encoding="utf-8")

    result = evaluate_multi([
        {"family": "Cerber", "pred_report_path": str(pred_1), "labels_path": str(labels_1)},
        {"family": "Cerber", "pred_report_path": str(pred_2), "labels_path": str(labels_2)},
    ])

    cerber = result["per_family"]["Cerber"]
    assert cerber["tp"] == 1
    assert cerber["fn"] == 1
    assert abs(cerber["recall"] - 0.5) < 1e-6


def test_consistency_score_perfect_agreement():
    votes = [
        {"suspicious_processes": [{"pid": 10}, {"pid": 20}]},
        {"suspicious_processes": [{"pid": 10}, {"pid": 20}]},
        {"suspicious_processes": [{"pid": 10}, {"pid": 20}]},
    ]
    result = consistency_score(votes)
    assert result["valid_runs"] == 3
    assert result["perfect_agreement"] is True
    assert result["unique_pid_sets"] == 1
    assert result["mean_agreement_rate"] == 1.0


def test_consistency_score_partial_agreement():
    votes = [
        {"suspicious_processes": [{"pid": 10}]},
        {"suspicious_processes": [{"pid": 10}, {"pid": 99}]},
        {"suspicious_processes": [{"pid": 10}]},
    ]
    result = consistency_score(votes)
    assert result["valid_runs"] == 3
    assert result["perfect_agreement"] is False
    assert result["unique_pid_sets"] == 2
    assert result["mean_agreement_rate"] < 1.0
    assert result["per_pid_support"]["10"] == 3
    assert result["per_pid_support"]["99"] == 1


def test_consistency_score_skips_api_errors():
    votes = [
        {"suspicious_processes": [{"pid": 5}]},
        {"api_error": "timeout", "suspicious_processes": []},
        {"suspicious_processes": [{"pid": 5}]},
    ]
    result = consistency_score(votes)
    assert result["total_runs"] == 3
    assert result["valid_runs"] == 2


def test_consistency_score_empty():
    result = consistency_score([])
    assert result["valid_runs"] == 0
    assert result["perfect_agreement"] is False
