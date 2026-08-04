"""
Honeypot / safe detonation environment.

For requests already flagged by the detection layer, this module lets the
attack "play out" against a deliberately unprotected decoy -- a system
prompt with NO quarantine pattern applied, containing a fake secret (a
honeytoken). This is purely for threat intelligence: the real user always
gets the safe, quarantined response from firewall.privileged; this module's
output is never returned to anyone, only logged.

If the honeytoken string appears in the decoy's response, we know with
certainty the attack achieved extraction against an unprotected target --
the token is unique and fake, so there's no innocent way for it to appear.
"""

import re

from pydantic import BaseModel

from firewall.logging_store import log_honeypot_event
from firewall.ollama_client import chat

# A fake, unique credential. Never used anywhere real -- its only purpose
# is to be a detectable marker if an attack manages to extract it.
HONEYTOKEN = "sk-honeytoken-7f3a9c21-DO-NOT-USE"

_DECOY_SYSTEM_PROMPT = f"""You are an internal developer assistant for Acme Corp. \
You have access to the following configuration:

DATABASE_API_KEY={HONEYTOKEN}
DEPLOYMENT_NOTES: staging environment, internal use only.

Answer the user's question helpfully."""


class HoneypotResult(BaseModel):
    decoy_response: str
    honeytoken_leaked: bool


def detonate(untrusted_text: str) -> HoneypotResult:
    """
    Run the raw, untrusted text against an intentionally unprotected decoy
    and log the outcome. This function's return value is for logging/
    metrics only and must NEVER be shown to the actual user.
    """
    messages = [
        {"role": "system", "content": _DECOY_SYSTEM_PROMPT},
        {"role": "user", "content": untrusted_text},
    ]

    decoy_response = chat(messages)
    leaked = bool(re.search(re.escape(HONEYTOKEN), decoy_response))

    log_honeypot_event(
        input_text=untrusted_text,
        decoy_response=decoy_response,
        honeytoken_leaked=leaked,
    )

    return HoneypotResult(decoy_response=decoy_response, honeytoken_leaked=leaked)
