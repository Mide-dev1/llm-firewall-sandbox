# Architecture

## Threat model

LLM-integrated applications collapse two things that should stay separate
into one channel: developer instructions and untrusted content (user
input, documents, web pages) all become plain text inside the same
context window. This project defends against three consequences of that:

- **Prompt injection** — attacker-supplied text that the model obeys as if
  it were a legitimate instruction. *Direct* injection: the attacker types
  it themselves. *Indirect* injection: it's hidden inside a document or
  page the model reads on someone else's behalf.
- **Data exfiltration** — the model is manipulated into leaking something
  it shouldn't (a system prompt, a secret, another user's data), usually
  chained after a successful injection.
- **Insecure output handling** — trusting the model's output without
  validation, letting a hijacked response cause real damage downstream
  (code execution, XSS, leaked secrets).

## Pipeline overview

```
User prompt
    -> Sanitizer (regex/keyword rules)
    -> Vector-similarity filter (embedding comparison against known attacks)
    -> Risk classifier (flagged / clean)
         -> [flagged] Honeypot: safe detonation + logging
         -> [clean]   Quarantined LLM (Q-LLM): extracts structured data only,
                       never has tools or memory
    -> Privileged LLM (P-LLM): has tools, only ever sees Q-LLM's structured
                       output, never raw untrusted text
    -> Ollama model (local backend)
    -> Output validator
    -> Response
```

## Defense layers

### 1. Rule-based sanitizer
Fast regex/keyword matching against known attack phrasings (instruction
override, role-play jailbreak, prompt extraction, obfuscation). Cheap and
explainable, but brittle — exact phrasing variance defeats it easily.

### 2. Vector-similarity filter
Embeds incoming prompts (`all-MiniLM-L6-v2`) and compares them against a
database of known-attack embeddings (ChromaDB, cosine similarity). Catches
attacks that don't use exact trigger phrases but are semantically close to
known ones. Threshold tuned empirically (see `docs/results.md`).

### 3. Combined decision: OR, not AND
A prompt is flagged if **either** layer flags it. The two layers catch
largely different attack types (exact-phrase vs. semantic similarity), so
requiring agreement between them would only catch attacks that fool
neither — a much weaker outcome than the union of both.

### 4. Quarantined / privileged LLM pattern
Rather than relying on detection alone, every request (flagged or not)
still passes through a structural safeguard: a quarantined LLM (Q-LLM)
that may read untrusted content but has no tools, no memory, and no
ability to act — it only returns constrained, structured data. A
privileged LLM (P-LLM) has real capabilities (tool access) but never
reads raw untrusted content directly, only the Q-LLM's structured output.
This means detection layers don't need to be perfect: even a missed
attack has nothing dangerous to reach if it slips past the filters,
because the component with real privileges never saw it directly.

### 5. Honeypot sandbox
Prompts flagged as suspicious are routed to an isolated environment where
the injection is allowed to "play out" against fake resources, with every
step logged — the source of the attack metrics and dashboard data.

### 6. Output validation
The model's response is checked before it reaches the caller — no
unescaped HTML, no unexpected tool-call syntax, size/format checks — so a
hijacked response can't be blindly trusted either.

## Why detection thresholds are tuned for balance, not maximum recall
Because the quarantine pattern (above) is a structural backstop, the
detection layers are tuned for the best precision/recall balance (F1)
rather than chasing maximum recall — a missed detection is a smaller
problem here than in a system relying on detection alone.

## Stack
Python · FastAPI · Ollama (local LLM backend) · ChromaDB ·
sentence-transformers · Pydantic · pytest

## Dataset
Qualifire Prompt Injections Benchmark (5,000 labeled prompts, benign vs.
jailbreak), via Hugging Face (`rogue-security/prompt-injections-benchmark`,
CC-BY-NC-4.0).
