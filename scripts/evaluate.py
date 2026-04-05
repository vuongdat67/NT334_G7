import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluation.metrics import evaluate
from src.cli.help_format import build_standard_parser


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="evaluate.py",
        description="Evaluate one triage report against one labels JSON file.",
        examples=[
            "python scripts/evaluate.py --pred results/triage_report.json --labels results/labels_example.json",
        ],
    )
    parser.add_argument("--pred", required=True, help="Path to prediction report JSON")
    parser.add_argument("--labels", required=True, help="Path to labels JSON")
    args = parser.parse_args()

    result = evaluate(args.pred, args.labels)
    print(json.dumps(result, ensure_ascii=True, indent=2))
