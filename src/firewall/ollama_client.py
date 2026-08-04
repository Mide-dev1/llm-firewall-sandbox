"""
Thin wrapper around Ollama's local REST API.

Ollama runs as a background service on your machine (default port 11434)
and exposes a simple HTTP API -- no cloud calls, no API key. This module
is the ONLY place in the codebase that talks to Ollama directly; every
other module (Q-LLM, P-LLM) goes through this, so if we ever swap the
backend (a different local model, a hosted API) we only change one file.
"""

import os

import httpx
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:latest")
DEFAULT_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "180"))


class OllamaConnectionError(Exception):
    """Raised when Ollama isn't reachable -- e.g. the app isn't running."""


def chat(
    messages: list[dict],
    model: str | None = None,
    timeout: float | None = None,
    json_mode: bool = False,
) -> str:
    """
    Send a chat-style message list to Ollama and return the assistant's
    reply text.

    messages: list of {"role": "system" | "user" | "assistant", "content": str}
    json_mode: if True, tells Ollama to constrain output to valid JSON.
        Used by the quarantined LLM, where we need a guaranteed-parseable
        structured response rather than free-form text.
    timeout: seconds to wait. Defaults to OLLAMA_TIMEOUT (180s) -- CPU-bound
        local generation can legitimately take a while, especially with
        json_mode and longer system prompts.
    """
    payload = {
        "model": model or DEFAULT_MODEL,
        "messages": messages,
        "stream": False,  # simpler for now -- get the full response at once
    }
    if json_mode:
        payload["format"] = "json"

    try:
        response = httpx.post(
            f"{BASE_URL}/api/chat",
            json=payload,
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUT,
        )
        response.raise_for_status()
    except httpx.ConnectError as e:
        raise OllamaConnectionError(
            f"Could not reach Ollama at {BASE_URL}. Is it running? "
            f"(try `ollama serve` or just opening the Ollama app)"
        ) from e
    except httpx.ReadTimeout as e:
        raise OllamaConnectionError(
            f"Ollama did not respond within {timeout or DEFAULT_TIMEOUT}s. "
            f"CPU-bound generation can be slow -- try increasing OLLAMA_TIMEOUT "
            f"in your .env, or use a smaller/faster model."
        ) from e

    data = response.json()
    return data["message"]["content"]
