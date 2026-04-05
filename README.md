# volGPT Reproduction and Improvement (Course Project)

This repository starts a fresh implementation inspired by the paper:
volGPT: Evaluation on triaging ransomware process in memory forensics with Large Language Model (FSI:DI, 2024).

## 1) Project Goal

Build a reproducible memory-forensics triage pipeline:

1. Memory dump input
2. Volatility 3 plugins (`windows.pslist`, `windows.vadinfo`, `windows.malfind`)
3. Structured JSON artifacts
4. Prompt-based LLM triage (majority voting, 3 runs)
5. Evaluation with Accuracy, Precision, Recall, F1, and Triage Efficiency
6. Hallucination-oriented error analysis

This implementation follows your selected scope:

- Reproduce first, then improve
- Phase 1 dataset: Arfeen 2020 only
- API budget target: <= 20 USD

## 2) Safety Rules (Mandatory)

- Do not execute ransomware binaries on host OS.
- Use memory dumps only for Phase 1.
- Keep analysis inside WSL2 Ubuntu or isolated VM/container.
- Never commit API keys, memory dumps, or sensitive outputs.

## 3) Current Structure

- `src/`: core modules
- `src/cli/main.py`: unified command surface (`volgpt`)
- `src/prompts/`: rich triage prompt modules (`triage_prompt.py`)
- `config/`: prompt template and decision rules
- `scripts/`: compatibility entry points (all callable via unified CLI)
- `results/`: output artifacts
- `docs/`: design notes and experiment notes
- `tests/`: test stubs

### 3.1 Recommended minimal config set (keep it simple)

Use only these files day-to-day:

1. `config/config.json` (main runtime config)
2. `config/provider_profiles.json` (provider switching map)
3. `config/model_profiles.json` (model comparison list)
4. `.env` (keys + default paths/category/experiment)

In `config/`, the core runtime JSON files are `config.json`, `provider_profiles.json`, and `model_profiles.json`.

## 4) Quick Start (WSL2 Ubuntu)

### 4.1 Create Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4.2 Environment variables

Copy one provider-focused template and edit values:

```bash
cp .env.gemini.example .env
# or
cp .env.openrouter.example .env
# or
cp .env.claude.example .env
```

You can also start from the generic template:

```bash
cp .env.example .env
```

Set variables based on your provider:

- Local model (LM Studio/Ollama): `LOCAL_LLM_API_KEY=local-not-needed`
- Gemini AI Studio: `GEMINI_API_KEY=...`
- OpenRouter fallback: `OPENROUTER_API_KEY=...`
- OpenAI cloud (optional): `OPENAI_API_KEY=...`

You can also set run defaults in `.env` (model, dump path, experiment name, results root).

Recommended selector variables:

- `LLM_PROVIDER` (`gemini` | `openrouter` | `openai` | `lmstudio` | `ollama`)
- `PROVIDER_PROFILES_PATH=config/provider_profiles.json`

Important: if you set multiple cloud keys in `.env` (for example both `OPENROUTER_API_KEY` and `GEMINI_API_KEY`), set `LLM_PROVIDER` explicitly.
Otherwise config loading will fail to prevent ambiguous provider selection.

### 4.3 Configure project

Edit `config/config.json` once, then mostly control provider/model from `.env`:

```bash
nano config/config.json
```

Update:

- `volatility_script_path`
- optional fallback values in config if `.env` is empty

Prompt strategy fields in `config/config.json`:

- `prompt_strategy`: `basic` | `chain_of_thought` | `few_shot` | `high_recall`
- `prompt_profile`: `legacy` | `n2` (richer prompt module inspired by n2-volgpt)
- `ransomware_hint`: family hint for few-shot examples
- `prompt_hallucination_check`: add anti-hallucination guard in prompt
- `prompt_recall_boost`: if true, bias prompt toward reducing false negatives

Provider fields in `config/config.json`:

- `llm_provider`
- `provider_profiles_path`

Recommended provider switching in `.env`:

- LM Studio: `LLM_BASE_URL=http://127.0.0.1:1234/v1`, `LLM_API_KEY_ENV=LOCAL_LLM_API_KEY`
- Ollama: `LLM_BASE_URL=http://127.0.0.1:11434/v1`, `LLM_API_KEY_ENV=LOCAL_LLM_API_KEY`
- OpenRouter: `LLM_BASE_URL=https://openrouter.ai/api/v1`, `LLM_API_KEY_ENV=OPENROUTER_API_KEY`

Profile-first switching (cleanest):

- Gemini AI Studio (free key):
  - `LLM_PROVIDER=gemini`
  - `GEMINI_API_KEY=...`
  - `GEMINI_MODEL=gemini-2.0-flash`
- OpenRouter:
  - `LLM_PROVIDER=openrouter`
  - `OPENROUTER_API_KEY=...`
  - `OPENROUTER_MODEL=qwen/qwen3.6-plus:free`
- OpenAI:
  - `LLM_PROVIDER=openai`
  - `OPENAI_API_KEY=...`
  - `OPENAI_MODEL=gpt-4o-mini`
- Claude via OpenRouter:
  - `LLM_PROVIDER=claude`
  - `OPENROUTER_API_KEY=...`
  - `CLAUDE_MODEL=anthropic/claude-3.7-sonnet`

Both local providers and OpenRouter are supported through the same OpenAI-compatible client.
If `LLM_BASE_URL` points to localhost/WSL private IP, auth key can stay `LOCAL_LLM_API_KEY=local-not-needed`.

Detailed provider switching guide: `docs/PROVIDER_SETUP.md`.
Comparison and adopted upgrades from n2-volgpt: `docs/N2_COMPARISON_AND_UPGRADE.md`.

### 4.4 Unified CLI

Use one command surface for all workflows:

```bash
python scripts/volgpt.py -h
```

Subcommand help:

```bash
python scripts/volgpt.py pipeline -- -h
python scripts/volgpt.py compare-models -- -h
python scripts/volgpt.py pipeline --script-help
```

Available subcommands include:

- `health`
- `pipeline`
- `batch`
- `download`
- `manifest`
- `subset`
- `smoke`
- `labels`
- `compare-models`
- `benchmark`
- `baseline-rule`
- `baseline-xgb`
- `report-model`
- `report-final`
- `evaluate`

### 4.4.1 Quick test command (pytest)

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && pytest -q'
```

### 4.4.2 One-snapshot smoke flow (end-to-end)

Single command:

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py smoke -- --config config/config.json --ground-truth-config config/ground_truth_process_names.json --category all --snapshot-index 0 --out-dir results/smoke_one_shot'
```

If you keep multiple provider keys in `.env`, pass provider explicitly:

```bash
python scripts/volgpt.py smoke -- --provider openrouter --config config/config.json --ground-truth-config config/ground_truth_process_names.json
```

Manual equivalent (advanced):

```bash
# 1) Refresh manifest to match current data layout
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py manifest -- --data-dir data --out-json results/snapshot_manifest.json --out-csv results/snapshot_manifest.csv'

# 2) Create one-row smoke manifest
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python - <<"PY"
import json
from pathlib import Path
rows = json.loads(Path("results/snapshot_manifest.json").read_text(encoding="utf-8"))
Path("results/snapshot_manifest_smoke_1.json").write_text(json.dumps(rows[:1], ensure_ascii=True, indent=2), encoding="utf-8")
PY'

# 3) Labels + batch run for one snapshot
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py labels -- --config config/config.json --manifest results/snapshot_manifest_smoke_1.json --ground-truth-config config/ground_truth_process_names.json --limit 1 --out-dir results/labels_smoke_1 --summary-json results/labels_smoke_1/labels_summary.json'
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py batch -- --config config/config.json --manifest results/snapshot_manifest_smoke_1.json --limit 1 --out-dir results/smoke_cli_batch_1'
```

### 4.5 Run pipeline

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py pipeline -- --config config/config.json'
```

Explicit config path (optional):

```bash
python scripts/volgpt.py pipeline -- --config config/config.json
```

Required env var for OpenRouter:

```bash
export OPENROUTER_API_KEY="your_key_here"
```

### 4.5.1 Health check before full triage

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py health -- --config config/config.json --strict'
```

With multiple keys in `.env`, select provider explicitly for this run:

```bash
python scripts/volgpt.py health -- --provider openrouter --config config/config.json --strict
```

This command will:

1. List exact model IDs from your endpoint.
2. Check whether `llm_model` in config exists.
3. Send a tiny ping request and print latency.

Useful flags:

- `--skip-ping`: endpoint/model probe only
- `--strict`: return non-zero on endpoint/model mismatch

If you are running from WSL and a configured host IP times out, the health check will automatically probe common alternatives (`localhost`, `127.0.0.1`, and WSL nameserver host IP) and both path styles (`/v1`, `/api/v1`).

Outputs:

- `results/triage_report.json`
- `results/triage_votes.json`

### 4.5.2 Conservative post-filter (false-positive reduction)

The pipeline now supports a conservative post-filter layer after LLM voting.

- Purpose: reduce benign false positives on system processes.
- Method: system-process allowlist + parent-child sanity checks + low-confidence generic-reason suppression.

Config fields:

- `post_filter_enabled`: enable/disable the filter layer
- `post_filter_min_conf_keep_for_allowlisted`: confidence threshold for allowlisted processes

When enabled, output report includes a `post_filter` section with dropped items and applied rules.

### 4.5.3 Volatility collection parallelism (optional)

To speed up plugin collection on stronger machines, configure in `config/config.json`:

- `volatility_parallel_plugins`: true/false
- `volatility_max_workers`: integer (recommended 2 to 3)

Default remains conservative (`false`) for stability.

### 4.6 Run evaluation

```bash
python scripts/evaluate.py \
  --pred results/triage_report.json \
  --labels results/labels_example.json
```

### 4.6.1 Incremental download from Dataverse (recommended for low-RAM/low-thermal laptops)

You do not need to pull all snapshots at once. Use incremental download with resume:

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py download -- --doi "doi:10.7910/DVN/YVL3CW" --out-dir data --name-regex "(?i)\.elf$" --snapshot-start 1 --snapshot-end 120 --max-files 30 --dry-run'
```

Then run real download (remove `--dry-run`):

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python scripts/volgpt.py download -- --doi "doi:10.7910/DVN/YVL3CW" --out-dir data --name-regex "(?i)\.elf$" --snapshot-start 1 --snapshot-end 120 --max-files 30 --resume'
```

Notes:

- `--resume` skips files already downloaded with matching size.
- Use snapshot ranges to grow dataset gradually (for example ransomware-only windows).
- If you mirror the dataset to Kaggle, you can also use Kaggle CLI (`kaggle datasets download ...`), but it is still script-triggered, not automatic by model itself.

### 4.7 Build snapshot manifest from author dataset

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.build_snapshot_manifest --data-dir data --out-json results/snapshot_manifest.json --out-csv results/snapshot_manifest.csv'
```

This creates a per-snapshot inventory with inferred executable family and category based on the published snapshot range mapping.

### 4.8 Run batch triage from manifest

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.run_batch_from_manifest --config config/config.json --manifest results/snapshot_manifest.json --category all --out-dir results/batch'
```

For your current downloads (benign only), you can run:

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.run_batch_from_manifest --config config/config.json --manifest results/snapshot_manifest.json --category benign --out-dir results/batch_benign'
```

### 4.8.1 Build per-snapshot labels by intersection (paper-style)

This follows the paper idea: intersection between runtime candidate process names and `windows.pslist` names.

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.build_labels_intersection --config config/config.json --manifest results/snapshot_manifest.json --ground-truth-config config/ground_truth_process_names.json --category all --out-dir results/labels'
```

Outputs:

- `results/labels/<snapshot>.labels.json`
- `results/labels/labels_summary.json`

### 4.8.2 Build a subset manifest (for limited storage/compute)

Use this to benchmark incrementally without loading full dataset.

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.build_benchmark_subset_manifest --manifest results/snapshot_manifest.json --out-json results/snapshot_manifest_subset.json --out-csv results/snapshot_manifest_subset.csv --max-benign 5 --max-benign-tool 5 --max-ransomware-per-family 3'
```

Then pass `results/snapshot_manifest_subset.json` to labels/model-comparison/benchmark scripts.

### 4.9 Model comparison tracker (paper-style)

Prepare a model definition list (name + provider + token_B metadata):

```bash
nano config/model_profiles.json
```

Set `enabled: true/false` per model to quickly turn models on or off.

Optional per-model overrides in the profile file:

- `llm_provider`
- `llm_reasoning_enabled`
- `llm_force_json_response_format`
- `llm_timeout_seconds`
- `llm_max_output_tokens`
- `temperature`
- `prompt_profile`
- `prompt_strategy`
- `ransomware_hint`
- `prompt_hallucination_check`
- `prompt_recall_boost`

Run cross-model comparison:

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.run_model_comparison --base-config config/config.json --model-profiles config/model_profiles.json --manifest results/snapshot_manifest.json --category all --experiment-name quick_profiles_v1'
```

Default behavior: skip a model after its first parse/API error (good for free-tier limits and incompatible endpoints).

- `.env`: `SKIP_MODEL_ON_ERROR=true`
- CLI override: `--no-skip-model-on-error`

Generate Markdown comparison table (model-by-model summary):

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.export_model_comparison_markdown --tracker-csv results/experiments/quick_profiles_v1/tracker/experiment_tracker.csv --manifest results/snapshot_manifest.json --title "Quick Model Comparison - volGPT"'
```

Tracker CSV columns (exact):

- `snapshot`
- `model`
- `provider`
- `suspicious_count`
- `dropped_by_post_filter`
- `runtime_seconds`
- `parse_error/api_error`

The summary CSV adds model definition context (`token_B`) and per-model averages for report tables.

Output organization (automatic):

- `results/experiments/<experiment-name>/runs/<model>/<snapshot>/report.json`
- `results/experiments/<experiment-name>/runs/<model>/<snapshot>/votes.json`
- `results/experiments/<experiment-name>/runs/<model>/<snapshot>/artifacts.json`
- `results/experiments/<experiment-name>/tracker/experiment_tracker.csv`
- `results/experiments/<experiment-name>/tracker/model_comparison_summary.csv`
- `results/experiments/<experiment-name>/tracker/experiment_tracker.json`

### 4.10 Family-level benchmark and paper-style table

After model comparison and labels generation:

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.run_family_benchmark --tracker-json results/experiments/quick_profiles_v1/tracker/experiment_tracker.json --manifest results/snapshot_manifest.json --labels-dir results/labels --paper-model qwen/qwen3.6-plus:free --out-dir results/benchmark/quick_profiles_v1'
```

Outputs:

- `results/benchmark/<exp>/snapshot_metrics.csv`
- `results/benchmark/<exp>/family_summary.csv`
- `results/benchmark/<exp>/overall_summary.csv`
- `results/benchmark/<exp>/paper_style_table.csv`
- `results/benchmark/<exp>/paper_style_table.md`

The benchmark includes hallucination taxonomy counters:

- `type_name_count`
- `type_relationship_count`
- `type_cascade_count`

### 4.11 Rule baseline (for required model-vs-baseline comparison)

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.run_rule_baseline --config config/config.json --manifest results/snapshot_manifest.json --labels-dir results/labels --ground-truth-config config/ground_truth_process_names.json --category all --out-dir results/baseline_rule'
```

Outputs:

- `results/baseline_rule/baseline_snapshot_metrics.csv`
- `results/baseline_rule/baseline_family_summary.csv`

### 4.11.1 XGBoost baseline (process-level ML baseline)

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.run_xgboost_baseline --config config/config.json --manifest results/snapshot_manifest.json --labels-dir results/labels --category all --out-dir results/baseline_xgboost/full_chain_current_data'
```

Outputs:

- `results/baseline_xgboost/<exp>/xgb_process_features.csv`
- `results/baseline_xgboost/<exp>/xgb_process_predictions.csv`
- `results/baseline_xgboost/<exp>/xgb_family_summary.csv`
- `results/baseline_xgboost/<exp>/xgb_overall_summary.json`
- `results/baseline_xgboost/<exp>/xgb_feature_importance.csv`
- `results/baseline_xgboost/<exp>/xgb_paper_style_table.md`

### 4.12 Course deliverable templates

Use provided templates under `deliverables/`:

- `deliverables/report/main.tex`
- `deliverables/slides/outline.md`
- `deliverables/demo/video_demo_checklist.md`
- `deliverables/same_simplified_improved.md`

### 4.13 Export final comparison table (LLM vs Rule vs XGBoost)

```bash
wsl bash -lc 'cd /mnt/c/Users/vuong/Documents/volGPT/volGPT && source .venv/bin/activate && python -m scripts.export_final_comparison_table --llm-model qwen/qwen3.6-plus:free --out-dir results/final_comparison/full_chain_current_data'
```

Outputs:

- `results/final_comparison/<exp>/final_overall_comparison.csv`
- `results/final_comparison/<exp>/final_family_comparison_long.csv`
- `results/final_comparison/<exp>/final_family_comparison_wide.csv`
- `results/final_comparison/<exp>/final_comparison_report.md`

## 5) Phase Plan

- Phase A: Environment + Volatility 3 validation
- Phase B: Data + labeling prep
- Phase C: Baseline reproduction pipeline
- Phase D: Metrics + family-level analysis
- Phase E: Hallucination reduction (prompt hardening)
- Phase F: Optional ML baseline (XGBoost)

## 6) Local Model Recommendation (How many B?)

For this memory-triage task, recommended ranges are:

- Minimum usable: 7B
- Good local baseline: 8B to 10B
- Better reasoning: 14B (if your hardware can run it)

Given your current models, suggested order:

1. `glm 4.6 9.4B` (LM Studio) as main local baseline
2. `deepseek 8B` (Ollama) as second local baseline
3. `deepseekcode 6.7B` only as fallback (it is code-specialized, less ideal for forensic reasoning)
4. `llama7B` as minimum baseline

Why this range: process triage needs instruction following + structured JSON output + relationship reasoning; 8B-10B usually gives a better balance than 6B-7B.

## 7) Next Immediate Tasks

1. Connect Volatility 3 command on your machine and validate plugin outputs.
2. Place 1 sample memory dump and run end-to-end once.
3. Replace mock labels with real Arfeen labels.
4. Add prompt v2 and compare FP/FN changes.

## 8) Current Phase Status

- Current phase: Phase C (baseline reproduction) with cross-model experiment automation completed.
- In progress: Phase D (metrics and family-level analysis), especially false-positive comparison on selected stable free models.
- Blocker to watch: if `LLM_API_KEY_ENV` is empty in `.env`, all model runs will fail and produce meaningless comparison rows.
