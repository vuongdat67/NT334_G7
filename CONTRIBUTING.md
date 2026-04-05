# Contributing

## Environment

- Use WSL2 Ubuntu and project virtual environment.
- Standard command pattern:
  - wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m ...'

## Before opening a PR

1. Keep secrets out of git.
2. Ensure .env is not committed.
3. Do not commit memory dumps under data/.
4. Rebuild manifest and verify one pipeline run:
   - python -m scripts.build_snapshot_manifest --data-dir data --out-json results/snapshot_manifest.json --out-csv results/snapshot_manifest.csv
   - python -m scripts.run_pipeline --config config/config.json

## Model comparison workflow

1. Enable only the profiles you need in config/model_profiles.json.
2. Run comparison:
   - python -m scripts.run_model_comparison --base-config config/config.json --model-profiles config/model_profiles.json --manifest results/snapshot_manifest.json --category all --experiment-name quick_profiles_v1
3. Export markdown report:
   - python -m scripts.export_model_comparison_markdown --tracker-csv results/experiments/quick_profiles_v1/tracker/experiment_tracker.csv --manifest results/snapshot_manifest.json --title "Quick Model Comparison - volGPT"

## Notes

- SKIP_MODEL_ON_ERROR=true is recommended for free-tier OpenRouter models.
- If a model returns 429 or 400 incompatibility, the runner can skip that model automatically.
