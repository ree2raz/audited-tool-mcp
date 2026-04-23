.PHONY: install seed demo test eval clean

install:
	uv sync --all-extras
	@echo "Downloading Privacy Filter model weights (first time only)..."
	uv run python -c "from transformers import AutoTokenizer, AutoModelForTokenClassification; AutoTokenizer.from_pretrained('openai/privacy-filter'); AutoModelForTokenClassification.from_pretrained('openai/privacy-filter')"
	@echo "✓ Install complete"

seed:
	uv run python scripts/seed_data.py
	@echo "✓ Synthetic data seeded to data/synthetic_fs.sqlite"

demo:
	uv run python scripts/run_demo.py

test:
	uv run pytest tests/ -v

eval:
	uv run python eval/eval_harness.py

clean:
	rm -f data/synthetic_fs.sqlite
	rm -f audit.jsonl
	rm -f vault.jsonl
	rm -f review_queue.jsonl
	@echo "✓ Cleaned generated files"
