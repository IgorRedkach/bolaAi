#!/usr/bin/env python3
"""Run the BOLA AI API locally (no Docker). Requires Ollama for /analyze."""
import os
import sys

# Ensure src is on path when run as python run_api.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import uvicorn
from bola_ai.api.app import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "run_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
