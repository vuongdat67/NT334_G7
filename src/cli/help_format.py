import argparse
from typing import Dict, List


DEFAULT_EXIT_CODES = {
    0: "Success",
    1: "Runtime/configuration error",
    2: "Input/validation error",
}


def build_standard_parser(
    prog: str,
    description: str,
    examples: List[str],
    exit_codes: Dict[int, str] | None = None,
) -> argparse.ArgumentParser:
    codes = exit_codes or DEFAULT_EXIT_CODES

    lines: List[str] = []
    lines.append("Examples:")
    for ex in examples:
        lines.append(f"  {ex}")

    lines.append("")
    lines.append("Exit codes:")
    for code in sorted(codes.keys()):
        lines.append(f"  {code}: {codes[code]}")

    return argparse.ArgumentParser(
        prog=prog,
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="\n".join(lines),
    )
