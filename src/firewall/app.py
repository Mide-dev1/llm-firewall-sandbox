"""
The live firewall service. Every request goes through:

    sanitizer + vector filter (flag for logging/scrutiny, does not gate)
    -> quarantined LLM (ALWAYS -- no exceptions, by design)
    -> privileged LLM (only ever sees the Q-LLM's structured output)
    -> output validator
    -> logged to SQLite
    -> response

Every request goes through the full quarantine pattern regardless of
whether detection flagged it -- detection results are recorded for
scrutiny/metrics, not used to decide whether quarantine applies.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from firewall.honeypot import detonate as honeypot_detonate
from firewall.logging_store import init_db, log_request
from firewall.output_validator import validate
from firewall.pipeline import evaluate as run_detection
from firewall.privileged import respond
from firewall.quarantine import extract

FALLBACK_MESSAGE = "I generated a response, but it failed a safety check and could not be returned."


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="LLM Application Firewall", lifespan=lifespan)


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str
    flagged: bool
    sanitizer_categories: list[str]
    vector_similarity: float
    qllm_contains_embedded_instruction: bool
    output_safe: bool


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    detection = run_detection(request.message)

    # Honeypot detonation is purely for threat intelligence -- it never
    # influences what the real user receives. Only runs for flagged
    # requests, since detonating every clean request would be wasted work.
    if detection.flagged:
        honeypot_detonate(request.message)

    qllm_result = extract(request.message)
    response_text = respond(qllm_result)

    validation = validate(response_text)
    final_response = response_text if validation.safe else FALLBACK_MESSAGE

    log_request(
        input_text=request.message,
        flagged=detection.flagged,
        sanitizer_categories=[c.value for c in detection.sanitizer_categories],
        vector_similarity=detection.vector_similarity,
        qllm_contains_embedded_instruction=qllm_result.contains_embedded_instruction,
        qllm_topic=qllm_result.topic_category,
        response_text=response_text,
        output_safe=validation.safe,
        output_validator_reasons=validation.reasons,
    )

    return ChatResponse(
        response=final_response,
        flagged=detection.flagged,
        sanitizer_categories=[c.value for c in detection.sanitizer_categories],
        vector_similarity=detection.vector_similarity,
        qllm_contains_embedded_instruction=qllm_result.contains_embedded_instruction,
        output_safe=validation.safe,
    )
