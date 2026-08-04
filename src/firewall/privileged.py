"""
The privileged LLM (P-LLM).

This is the component that actually generates the response the user sees.
Unlike the Q-LLM, it's allowed to have real capabilities (in a fuller
system: tool access, ability to take actions) -- but in exchange, it is
NEVER shown raw user text. It only ever receives the Q-LLM's structured,
validated output. Even a fully successful prompt injection in the
original text has nothing left to manipulate the P-LLM with, because the
P-LLM never reads that text at all.

If the Q-LLM flagged the input as containing an embedded instruction
attempt, the P-LLM refuses outright rather than trying to "helpfully"
respond to a manipulation attempt anyway -- this check happens BEFORE any
call to the model, so a confirmed attack never even reaches generation.
"""

from firewall.ollama_client import chat
from firewall.quarantine import QLLMOutput

_SYSTEM_PROMPT = """You are a helpful assistant. You do not see the user's \
original message -- you only receive a short, pre-extracted summary of \
their intent from a separate filtering system. Respond helpfully to that \
summarized intent."""

_REFUSAL_MESSAGE = (
    "I can't process this request -- it was flagged as containing an "
    "attempt to override my instructions rather than a genuine question."
)


def respond(qllm_output: QLLMOutput) -> str:
    """
    Generate the final response using ONLY the Q-LLM's structured output.
    Never receives or has access to the original raw user text.
    """
    if qllm_output.contains_embedded_instruction:
        return _REFUSAL_MESSAGE

    user_message = (
        f"Topic: {qllm_output.topic_category}\n"
        f"User intent: {qllm_output.user_intent_summary}\n\n"
        f"Write a helpful response to this request."
    )

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    return chat(messages)
