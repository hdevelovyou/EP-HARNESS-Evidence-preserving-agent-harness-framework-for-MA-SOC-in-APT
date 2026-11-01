"""Backward-compatible entrypoint delegating debate_based runs to the unified main.py pipeline."""

import sys

from main import (
    cli_main,
    run_cyber_defense_system,
    run_debate_cyber_defense_system,
    run_debate_soft_tests,
)

__all__ = [
    "run_cyber_defense_system",
    "run_debate_cyber_defense_system",
    "run_debate_soft_tests",
]


if __name__ == "__main__":
    raise SystemExit(cli_main(sys.argv[1:], default_strategy="debate_based"))
