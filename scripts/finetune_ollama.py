"""LoRA-finetune a local base model on admin-approved TrueSignal corrections,
then register the result as a new Ollama model tag.

This is the one step in the human-verified fine-tuning loop that this repo
cannot run for you: it needs a GPU, the optional `finetune` dependency group
(`pip install -e ".[finetune]"` -- torch/transformers/peft/trl/datasets), a
llama.cpp checkout for the GGUF conversion, and a multi-GB base-model
download. Everything upstream of this script (capturing verified
corrections, admin curation at /training, `truesignal export-training-data`)
runs today with no extra dependencies.

Usage:
    # validate the dataset and print the commands this would run -- no
    # download, no training, safe to run anywhere:
    python scripts/finetune_ollama.py --dry-run

    # the real run, on a machine with a GPU and the deps installed:
    python scripts/finetune_ollama.py --llama-cpp-path /path/to/llama.cpp

Then point the project at the result:
    OLLAMA_MODEL=truesignal-ft-<timestamp>
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_DATASET = PROJECT_ROOT / "training_data.jsonl"
DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"
STATE_DIR = PROJECT_ROOT / ".truesignal"
RUNS_LOG = STATE_DIR / "training_runs.json"


def _load_dataset(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"no dataset at {path} -- run `truesignal export-training-data --out {path}` first")
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if not records:
        raise SystemExit(f"{path} has no examples -- approve some corrections at /training first")
    return records


def _record_run(*, base_model: str, example_count: int, tag: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    entries = json.loads(RUNS_LOG.read_text()) if RUNS_LOG.exists() else []
    entries.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "base_model": base_model,
        "example_count": example_count,
        "resulting_tag": tag,
    })
    RUNS_LOG.write_text(json.dumps(entries, indent=2))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--dataset", type=Path, default=DEFAULT_DATASET, help="chat-SFT JSONL from export-training-data"
    )
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL, help="HF model id to LoRA-finetune")
    p.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / ".truesignal" / "finetune-out")
    p.add_argument(
        "--llama-cpp-path", type=Path, help="path to a llama.cpp checkout, for the GGUF conversion"
    )
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument(
        "--dry-run", action="store_true",
        help="validate the dataset and print the plan; nothing is downloaded or trained",
    )
    args = p.parse_args(argv)

    dataset = _load_dataset(args.dataset)
    tag = f"truesignal-ft-{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
    print(f"dataset: {args.dataset} ({len(dataset)} examples)")
    print(f"base model: {args.base_model}")
    print(f"output tag: {tag}")

    gguf_path = args.output_dir / "model.gguf"
    modelfile = args.output_dir / "Modelfile"
    plan = [
        f"# 1. LoRA-finetune {args.base_model} on {args.dataset} for {args.epochs} epoch(s) "
        f"-> {args.output_dir / 'adapter'}",
        f"# 2. merge adapter into base weights -> {args.output_dir / 'merged'}",
        f"# 3. convert to GGUF via llama.cpp "
        f"({args.llama_cpp_path or '<--llama-cpp-path required for a real run>'}) -> {gguf_path}",
        f"# 4. write {modelfile} with `FROM {gguf_path}`",
        f"# 5. ollama create {tag} -f {modelfile}",
    ]
    print("\nplan:")
    print("\n".join(plan))

    if args.dry_run:
        print("\n--dry-run: stopping here. No download, no training, no model created.")
        return 0

    required = ("peft", "torch", "transformers", "trl")
    missing = [pkg for pkg in required if importlib.util.find_spec(pkg) is None]
    if missing:
        raise SystemExit(
            f"\nmissing fine-tune dependencies: {', '.join(missing)}. Install them with:\n"
            "    pip install -e \".[finetune]\"\n"
            "and re-run without --dry-run. This also needs a GPU and will download "
            f"{args.base_model} (several GB) from Hugging Face -- make sure that's expected first."
        )
    if args.llama_cpp_path is None or not args.llama_cpp_path.exists():
        raise SystemExit(
            "--llama-cpp-path must point at a real llama.cpp checkout for the GGUF conversion step"
        )

    # The actual training loop is intentionally not implemented here: it
    # requires GPU compute and a real, reviewed base-model download that
    # this project cannot decide to kick off on your behalf. Wire in your
    # own trl.SFTTrainer call over `dataset` at this point, then the
    # merge/convert/ollama-create steps from the plan above.
    raise SystemExit(
        "dependencies and llama.cpp path look present, but the training loop itself "
        "is left for you to wire in here (see the module docstring) -- this script "
        "won't silently start a multi-hour GPU job or a multi-GB download on its own."
    )


if __name__ == "__main__":
    sys.exit(main())
