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
- `config/`: prompt template and decision rules
- `scripts/`: CLI entry points
- `results/`: output artifacts
- `docs/`: design notes and experiment notes
- `tests/`: test stubs

## 4) Quick Start (WSL2 Ubuntu)

### 4.1 Create Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4.2 Environment variables

Copy and edit `.env.example`:

```bash
cp .env.example .env
```

Set variables based on your provider:

- Local model (LM Studio/Ollama): `LOCAL_LLM_API_KEY=local-not-needed`
- OpenRouter fallback: `OPENROUTER_API_KEY=...`
- OpenAI cloud (optional): `OPENAI_API_KEY=...`

### 4.3 Configure project

Copy and edit config:

```bash
cp config/config.example.json config/config.local.json
```

Update:

- `volatility_script_path`
- `memory_dump_path`
- `llm_model`
- `llm_api_key_env`
- `llm_base_url`

### 4.4 Provider Presets

Use one of these example configs and copy to your local config:

- `config/config.local_lmstudio.example.json`
- `config/config.local_ollama.example.json`
- `config/config.openrouter.example.json`

Example:

```bash
cp config/config.local_lmstudio.example.json config/config.local.json
```

### 4.5 Run pipeline

```bash
python scripts/run_pipeline.py --config config/config.local.json
```

### 4.5.1 Health check before full triage

```bash
python -m scripts.health_check --config config/config.local.json
```

This command will:

1. List exact model IDs from your endpoint.
2. Check whether `llm_model` in config exists.
3. Send a tiny ping request and print latency.

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

### 4.6 Run evaluation

```bash
python scripts/evaluate.py \
  --pred results/triage_report.json \
  --labels results/labels_example.json
```

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
