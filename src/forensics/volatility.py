import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional


class VolatilityRunner:
    def __init__(self, vol_script_path: str, plugin_timeout_seconds: Optional[float] = None):
        self.vol_script_path = self._resolve_path(vol_script_path)
        self.plugin_timeout_seconds = plugin_timeout_seconds

    @staticmethod
    def _resolve_path(path_like: str) -> str:
        return str(Path(path_like).expanduser())

    @staticmethod
    def _extract_json_payload(stdout: str) -> Optional[dict]:
        text = (stdout or "").strip()
        if not text:
            return {"rows": []}

        # Fast path: pure JSON output.
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

        # Some Volatility runs may include progress/log lines before JSON.
        starts = sorted(set([i for i, ch in enumerate(text) if ch in "[{" ]))
        if not starts:
            return None

        for start in starts:
            sliced = text[start:]
            try:
                data = json.loads(sliced)
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    return {"rows": data}
            except json.JSONDecodeError:
                continue
        return None

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
        
        max_retries = 2
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.plugin_timeout_seconds,
                )
                if proc.returncode == 0:
                    break
                last_error = f"Return code {proc.returncode}. STDERR: {proc.stderr.strip()}"
            except subprocess.TimeoutExpired as e:
                last_error = f"Timeout after {self.plugin_timeout_seconds}s"
            except Exception as e:
                last_error = str(e)
            
            if attempt < max_retries:
                time.sleep(2 * (attempt + 1))
        else:
            raise RuntimeError(
                f"Volatility plugin failed after {max_retries + 1} attempts: "
                f"{plugin}\nCommand: {' '.join(cmd)}\nError: {last_error}"
            )

        stdout = proc.stdout.strip()
        if not stdout:
            return {"rows": []}

        extracted = self._extract_json_payload(stdout)
        if extracted is not None:
            return extracted

        # Keep truncated raw output for troubleshooting while protecting token budget.
        return {
            "raw_output": stdout[:5000],
            "parse_error": True,
        }

    def collect(
        self,
        memory_dump_path: str,
        plugins: List[str],
        parallel: bool = False,
        max_workers: int = 2,
    ) -> Dict[str, dict]:
        artifacts: Dict[str, dict] = {}

        if not parallel or len(plugins) <= 1:
            for plugin in plugins:
                artifacts[plugin] = self.run_plugin(memory_dump_path, plugin)
            return artifacts

        workers = max(1, min(int(max_workers), len(plugins)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(self.run_plugin, memory_dump_path, plugin): plugin
                for plugin in plugins
            }
            for fut in as_completed(fut_map):
                plugin = fut_map[fut]
                artifacts[plugin] = fut.result()

        # Keep deterministic key order in final payload.
        return {p: artifacts.get(p, {"rows": []}) for p in plugins}
