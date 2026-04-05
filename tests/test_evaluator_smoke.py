from src.evaluation.metrics import evaluate


def test_smoke(tmp_path):
    pred = tmp_path / "pred.json"
    labels = tmp_path / "labels.json"

    pred.write_text('{"suspicious_processes": [{"pid": 2}]}', encoding="utf-8")
    labels.write_text('{"all_pids": [1,2,3], "malicious_pids": [2]}', encoding="utf-8")

    out = evaluate(str(pred), str(labels))
    assert out["tp"] == 1
    assert out["accuracy"] >= 0
