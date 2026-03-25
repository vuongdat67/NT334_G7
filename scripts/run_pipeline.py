import argparse
import json

from src.pipeline import run_pipeline


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to config JSON file")
    args = parser.parse_args()

    report = run_pipeline(args.config)
    print(json.dumps(report, ensure_ascii=True, indent=2))
