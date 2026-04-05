import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser
from src.pipeline.runner import run_pipeline


if __name__ == "__main__":
    load_dotenv()

    parser = build_standard_parser(
        prog="run_pipeline.py",
        description="Run one triage inference for a single memory dump using config/config.json.",
        examples=[
            "python scripts/run_pipeline.py --config config/config.json",
        ],
    )
    parser.add_argument(
        "--config",
        default=os.getenv("BASE_CONFIG_FILE", "config/config.json"),
        help="Path to config JSON file",
    )
    args = parser.parse_args()

    report = run_pipeline(args.config)
    print(json.dumps(report, ensure_ascii=True, indent=2))
