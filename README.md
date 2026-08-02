# LLM Application Firewall & Prompt Injection Sandbox

A security proxy layer that intercepts, sanitizes, and evaluates prompts
before they reach a generative AI application — built to study and defend
against prompt injection, data exfiltration, and insecure output handling
in LLM-integrated systems.

## Status
🚧 Early development — Phase 1 (detection module) in progress.

## Why this project
AI-integrated applications can't reliably separate developer instructions
from untrusted user/document content, since both become plain text inside
the same context window. This project implements and evaluates layered
defenses against that class of vulnerability:

- Rule-based input sanitization
- Vector-similarity detection against a known-attack embedding database
- A quarantined/privileged dual-LLM pattern (untrusted content is only
  ever read by a tool-less, memory-less "quarantined" LLM)
- A honeypot sandbox that safely detonates suspected attacks and logs
  attacker behavior
- Output validation before any model response reaches the caller

## Architecture
See `docs/architecture.md` (coming soon).

## Stack
Python · FastAPI · Ollama (local LLM) · ChromaDB · sentence-transformers · pytest

## Dataset
Detection is evaluated against the Qualifire Prompt Injections Benchmark
(5,000 labeled prompts, jailbreak vs. benign), via Hugging Face
(`rogue-security/prompt-injections-benchmark`, CC-BY-NC-4.0).

## Setup
```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env            # then fill in your HF_TOKEN
```

## License
MIT (this project's code). Note the dataset itself is CC-BY-NC-4.0 —
non-commercial use only.
