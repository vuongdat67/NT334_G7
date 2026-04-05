import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCRIPT_REGISTRY = {
    "health": ("scripts/health_check.py", "Lightweight provider/model connectivity check"),
    "pipeline": ("scripts/run_pipeline.py", "Run one triage on memory dump from config"),
    "batch": ("scripts/run_batch_from_manifest.py", "Batch triage from manifest"),
    "download": ("scripts/download_dataverse_dataset.py", "Download snapshots from Dataverse DOI"),
    "manifest": ("scripts/build_snapshot_manifest.py", "Build snapshot manifest JSON/CSV from data folder"),
    "subset": ("scripts/build_benchmark_subset_manifest.py", "Build balanced benchmark subset manifest"),
    "smoke": ("scripts/run_smoke.py", "Run one-shot smoke flow (manifest -> labels -> batch -> evaluate)"),
    "labels": ("scripts/build_labels_intersection.py", "Build label files from process-name intersection"),
    "compare-models": ("scripts/run_model_comparison.py", "Run multi-model comparison on selected snapshots"),
    "benchmark": ("scripts/run_family_benchmark.py", "Run family-level benchmark and export metrics"),
    "baseline-rule": ("scripts/run_rule_baseline.py", "Run deterministic rule baseline"),
    "baseline-xgb": ("scripts/run_xgboost_baseline.py", "Run XGBoost baseline with train/test split"),
    "report-final": ("scripts/export_final_comparison_table.py", "Export final LLM vs Rule vs XGBoost table"),
    "report-model": ("scripts/export_model_comparison_markdown.py", "Export model-comparison markdown report"),
    "evaluate": ("scripts/evaluate.py", "Evaluate one prediction report against one labels file"),
}


def _run_script(script_rel_path: str, forwarded_args: list[str], dry_run: bool) -> int:
    script_path = PROJECT_ROOT / script_rel_path
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    args = list(forwarded_args)
    if args and args[0] == "--":
        args = args[1:]

    command = [sys.executable, str(script_path), *args]
    print("[volgpt] Executing:", " ".join(command))
    if dry_run:
        return 0

    proc = subprocess.run(command, cwd=str(PROJECT_ROOT), check=False)
    return int(proc.returncode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="volgpt",
        description="Unified CLI for volGPT pipelines, benchmarks, baselines, and reports.",
        epilog=(
            "Examples:\n"
            "  volgpt health -- --config config/config.json\n"
            "  volgpt pipeline -- --config config/config.json\n"
            "  volgpt batch -- --manifest results/snapshot_manifest.json --labels-dir results/labels\n"
            "  volgpt compare-models -- --category all --limit 30\n"
            "  volgpt smoke -- --config config/config.json --ground-truth-config config/ground_truth_process_names.json\n"
            "  volgpt report-final -- --out-dir results/final_comparison/full_chain_current_data"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print delegated command without executing.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, (script_path, desc) in SCRIPT_REGISTRY.items():
        sub = subparsers.add_parser(
            name,
            help=desc,
            description=f"{desc}. Delegates to {script_path}.",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        sub.add_argument(
            "args",
            nargs=argparse.REMAINDER,
            help=(
                "Arguments forwarded to the delegated script.\n"
                "Use '--' before script arguments, e.g.\n"
                f"  volgpt {name} -- -h"
            ),
        )
        sub.add_argument(
            "--script-help",
            action="store_true",
            help="Show delegated script help (equivalent to forwarding '-h').",
        )
        sub.set_defaults(script_path=script_path)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    script_path = getattr(args, "script_path", "")
    forwarded = list(getattr(args, "args", []))
    if bool(getattr(args, "script_help", False)):
        forwarded = ["-h"]

    try:
        return _run_script(script_path, forwarded, bool(args.dry_run))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"[volgpt] Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
