from src.pipeline.runner import attach_hidden_process_diff


def _rows(*pids):
    return {"rows": [{"PID": p, "ImageFileName": f"proc_{p}.exe"} for p in pids]}


def test_attach_hidden_process_diff_adds_summary():
    artifacts = {
        "windows.pslist": _rows(4, 100),
        "windows.psscan": _rows(4, 100, 999),
    }

    out = attach_hidden_process_diff(artifacts)

    assert "windows.hidden_process_diff" in out
    diff = out["windows.hidden_process_diff"]
    assert diff["hidden_pid_count"] == 1
    assert diff["hidden_pids"] == [999]


def test_attach_hidden_process_diff_no_psscan_noop():
    artifacts = {"windows.pslist": _rows(4, 100)}
    out = attach_hidden_process_diff(artifacts)
    assert "windows.hidden_process_diff" not in out
