"""BOLA analysis agent: RAG + LLM."""

from bola_ai.agent.runner import run_analysis

# Backward-compatible alias used by older scripts/import paths.
analyze_for_bola = run_analysis

__all__ = ["analyze_for_bola", "run_analysis"]
