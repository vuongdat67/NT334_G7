import json
import subprocess
from pathlib import Path
from typing import Dict, List


class VolatilityRunner:
    def __init__(self, vol_script_path: str):
        self.vol_script_path = self._resolve_path(vol_script_path)

    @staticmethod
    def _resolve_path(path_like: str) -> str:
        return str(Path(path_like).expanduser())

    def run_plugin(self, memory_dump_path: str, plugin: str) -> dict:
        resolved_dump = self._resolve_path(memory_dump_path)
        if not Path(self.vol_script_path).exists():
            raise FileNotFoundError(
                f"Volatility script not found: {self.vol_script_path}. "
                "Set volatility_script_path to an absolute or home-expanded path."
            )
        if not Path(resolved_dump).exists():
            raise FileNotFoundError(
                f"Memory dump not found: {resolved_dump}. "
                "Set memory_dump_path to an existing dump file."
            )

        cmd = [
            "python3",
            self.vol_script_path,
            "-q",
            "-f",
            resolved_dump,
            "-r",
            "json",
            plugin,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                "Volatility plugin failed: "
                f"{plugin}\nCommand: {' '.join(cmd)}\nSTDERR: {proc.stderr.strip()}"
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
