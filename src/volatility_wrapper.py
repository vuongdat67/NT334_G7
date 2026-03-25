import json
import subprocess
from typing import Dict, List


class VolatilityRunner:
    def __init__(self, vol_script_path: str):
        self.vol_script_path = vol_script_path

    def run_plugin(self, memory_dump_path: str, plugin: str) -> dict:
        cmd = [
            "python3",
            self.vol_script_path,
            "-f",
            memory_dump_path,
            plugin,
            "--output",
            "json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"Volatility plugin failed: {plugin}\nSTDERR: {proc.stderr.strip()}"
            )

        stdout = proc.stdout.strip()
        if not stdout:
            return {"rows": []}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            # Some plugin outputs may not be pure JSON depending on environment.
            return {"raw_output": stdout}

    def collect(self, memory_dump_path: str, plugins: List[str]) -> Dict[str, dict]:
        artifacts = {}
        for plugin in plugins:
            artifacts[plugin] = self.run_plugin(memory_dump_path, plugin)
        return artifacts
