from src.forensics.psscan_diff import detect_hidden_pids, _extract_pids


def _rows(*pids):
    return {"rows": [{"pid": p, "name": f"proc_{p}.exe"} for p in pids]}


def test_no_hidden_when_identical():
    pslist = _rows(4, 100, 200)
    psscan = _rows(4, 100, 200)
    diff = detect_hidden_pids(pslist, psscan)
    assert diff["hidden_pid_count"] == 0
    assert diff["hidden_pids"] == []


def test_detects_hidden_pid():
    pslist = _rows(4, 100)
    psscan = _rows(4, 100, 999)   # 999 is hidden
    diff = detect_hidden_pids(pslist, psscan)
    assert diff["hidden_pid_count"] == 1
    assert 999 in diff["hidden_pids"]


def test_hidden_rows_populated():
    pslist = _rows(4)
    psscan = _rows(4, 777)
    diff = detect_hidden_pids(pslist, psscan)
    assert len(diff["hidden_rows"]) == 1
    assert diff["hidden_rows"][0]["pid"] == 777


def test_terminated_pids_counted():
    # PIDs in pslist but not psscan → exited processes
    pslist = _rows(4, 100, 200)
    psscan = _rows(4, 100)   # 200 exited
    diff = detect_hidden_pids(pslist, psscan)
    assert diff["terminated_pid_count"] == 1


def test_both_none_returns_zeros():
    diff = detect_hidden_pids(None, None)
    assert diff["hidden_pid_count"] == 0
    assert diff["pslist_pid_count"] == 0


def test_list_format_artifacts():
    pslist = [{"pid": 10}, {"pid": 20}]
    psscan = [{"pid": 10}, {"pid": 20}, {"pid": 30}]
    diff = detect_hidden_pids(pslist, psscan)
    assert diff["hidden_pid_count"] == 1
    assert diff["hidden_pids"] == [30]


def test_extract_pids_handles_string_pid():
    artifact = {"rows": [{"pid": "42"}, {"pid": "not-a-pid"}, {"pid": 7}]}
    pids = _extract_pids(artifact)
    assert pids == {42, 7}
