"""Run the committed benign hard negatives with the shared benchmark runner.

Example:
    python3 benchmarks/run_fp_test.py --model qwen2.5:1.5b --headless --output /tmp/fp.jsonl
"""

import sys

from red_team_runner import main

if __name__ == "__main__":
    sys.exit(main(default_corpus="benign"))
