import time

from src.forensics.volatility import VolatilityRunner


def test_extract_json_payload_with_prefixed_logs():
    noisy = "[info] loading plugin...\n{\"rows\":[{\"pid\":1,\"name\":\"a.exe\"}]}"
    data = VolatilityRunner._extract_json_payload(noisy)
    assert isinstance(data, dict)
    assert data["rows"][0]["pid"] == 1


def test_extract_json_payload_array_fallback():
    data = VolatilityRunner._extract_json_payload('[{"pid":7}]')
    assert data == {"rows": [{"pid": 7}]}


def test_collect_parallel_preserves_plugin_order():
    class FakeRunner(VolatilityRunner):
        def run_plugin(self, memory_dump_path: str, plugin: str) -> dict:  # noqa: ARG002
            # Different delays to force completion order mismatch.
            delay = {"a": 0.03, "b": 0.01, "c": 0.02}[plugin]
            time.sleep(delay)
            return {"rows": [{"plugin": plugin}]}

    runner = FakeRunner("vol.py")
    plugins = ["a", "b", "c"]
    artifacts = runner.collect("dummy.elf", plugins, parallel=True, max_workers=3)

    assert list(artifacts.keys()) == plugins
    assert artifacts["a"]["rows"][0]["plugin"] == "a"
    assert artifacts["b"]["rows"][0]["plugin"] == "b"
    assert artifacts["c"]["rows"][0]["plugin"] == "c"
