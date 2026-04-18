import json
import subprocess
import sys
from pathlib import Path


def _write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def test_evaluate_extended_generates_output(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_extended.py"

    results_dir = tmp_path / "results_a"
    labels_dir = results_dir / "labels"

    _write_json(
        results_dir / "Snapshot_x.report.json",
        {"suspicious_processes": [{"pid": 10, "process_name": "x.exe", "reason": "malfind MZ"}]},
    )
    _write_json(
        results_dir / "Snapshot_x.votes.json",
        [{"suspicious_processes": [{"pid": 10}]}],
    )
    _write_json(
        labels_dir / "Snapshot_x.labels.json",
        {"family": "Cerber", "all_pids": [10, 20], "malicious_pids": [10]},
    )

    out_json = tmp_path / "extended_eval.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--results-dir",
            str(results_dir),
            "--out-json",
            str(out_json),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert out_json.exists()

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert "primary" in data
    assert data["primary"]["overall"]["snapshot_count"] == 1


def test_evaluate_extended_compare_builds_mcnemar(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_extended.py"

    results_a = tmp_path / "results_a"
    results_b = tmp_path / "results_b"
    labels_dir = results_a / "labels"

    _write_json(
        results_a / "Snapshot_y.report.json",
        {"suspicious_processes": [{"pid": 1}]},
    )
    _write_json(
        results_b / "Snapshot_y.report.json",
        {"suspicious_processes": []},
    )
    _write_json(
        labels_dir / "Snapshot_y.labels.json",
        {"family": "WannaCry", "all_pids": [1, 2], "malicious_pids": [1]},
    )

    out_json = tmp_path / "extended_compare.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--results-dir",
            str(results_a),
            "--compare-dir",
            str(results_b),
            "--out-json",
            str(out_json),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert "comparison" in data
    result = data["comparison"]["result"]
    assert result["matched_snapshots"] == 1
    assert result["mcnemar"] is not None
