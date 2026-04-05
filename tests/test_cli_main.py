from src.cli.main import SCRIPT_REGISTRY, build_parser, main


def test_cli_parser_accepts_known_subcommand():
    parser = build_parser()
    args = parser.parse_args(["health", "--", "--config", "config/config.json"])
    assert args.command == "health"
    assert args.script_path == SCRIPT_REGISTRY["health"][0]


def test_cli_main_dry_run_returns_zero():
    code = main(["--dry-run", "pipeline", "--", "--config", "config/config.json"])
    assert code == 0


def test_cli_main_script_help_dry_run_returns_zero():
    code = main(["--dry-run", "pipeline", "--script-help"])
    assert code == 0


def test_cli_parser_includes_smoke_command():
    parser = build_parser()
    args = parser.parse_args(["smoke", "--", "--category", "benign"])
    assert args.command == "smoke"
    assert args.script_path == SCRIPT_REGISTRY["smoke"][0]


def test_cli_main_smoke_dry_run_returns_zero():
    code = main(["--dry-run", "smoke", "--", "--category", "benign"])
    assert code == 0
