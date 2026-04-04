import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import run_pipeline


if __name__ == "__main__":
    load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to config JSON file")
    args = parser.parse_args()

    report = run_pipeline(args.config)
    print(json.dumps(report, ensure_ascii=True, indent=2))
