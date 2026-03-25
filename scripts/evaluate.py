import argparse
import json

from src.evaluator import evaluate


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pred", required=True, help="Path to prediction report JSON")
    parser.add_argument("--labels", required=True, help="Path to labels JSON")
    args = parser.parse_args()

    result = evaluate(args.pred, args.labels)
    print(json.dumps(result, ensure_ascii=True, indent=2))
