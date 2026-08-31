import re
from typing import Callable

from openai import OpenAI

from src.config import LLM_MODEL, LLM_TEMPERATURE, SYSTEM_PROMPT, USER_PROMPT_TEMPLATE

CITATION_RE = re.compile(r"\[([A-Za-z0-9._-]+__chunk\d{3})\]")
# OKF concept ids are bundle-relative paths ("metrics/revenue"), which the chunk
# pattern above cannot match — hence a second, looser pattern. It is looser than
# it looks safe to be ON PURPOSE: parse_concept_citations() below only trusts a
# match after checking it against the admitted set, so over-matching costs a
# rejected candidate, never an accepted one.
CONCEPT_CITATION_RE = re.compile(r"\[([A-Za-z0-9][A-Za-z0-9._/-]*)\]")


def _default_chunk_entry(c: dict) -> str:
    return f"[{c['chunk_id']}] (from: {c['title']})\n{c['text']}"


def generate(
    question: str,
    chunks: list[dict],
    client: OpenAI,
    *,
    system_prompt: str = SYSTEM_PROMPT,
    template: str = USER_PROMPT_TEMPLATE,
    format_entry: Callable[[dict], str] = _default_chunk_entry,
) -> str:
    """Build a cited answer from ``chunks`` using the configured LLM.

    The prompt instructs the model to embed chunk IDs inline as ``[chunk_id]``.
    Call ``parse_citations()`` on the returned string to extract those IDs.
    The answer hook (src/attestation.py) signs the answer + chunk hashes into
    an attestation object.

    The three keyword-only parameters let a different corpus reuse this call
    unchanged: src/enforce.py passes the OKF prompts and a concept formatter so
    admitted OKF concepts go through exactly this code path. Their defaults
    reproduce the arXiv behaviour exactly.
    """
    context_block = "\n\n".join(format_entry(c) for c in chunks)
    user_msg = template.format(question=question, context_block=context_block)
    response = client.chat.completions.create(
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
    )
    return response.choices[0].message.content


def parse_citations(answer: str) -> list[str]:
    """Extract chunk IDs cited by the LLM in the form ``[doc_id__chunkNNN]``.

    Returns IDs in first-appearance order with duplicates removed. These are
    non-cryptographic citations — integrity is not verified here; that is the
    job of the read hook (src/verifier.py / src/merkle.py's check_tamper).
    """
    return list(dict.fromkeys(CITATION_RE.findall(answer)))


def parse_concept_citations(
    answer: str, admitted_ids: list[str], known_ids: list[str]
) -> tuple[list[str], list[str]]:
    """Split an answer's bracketed OKF concept citations into (admitted, refused).

    The second list is the interesting one. src/enforce.py withholds refused
    concepts from the prompt entirely, but a model can still emit a concept id
    it saw in an earlier turn, inferred from a sibling path, or guessed — and an
    answer that cites a concept the gate REFUSED launders that concept's
    authority into the output even though its bytes never entered the context.
    So a refused citation is itself a refusal, not a formatting nit.

    `known_ids` is the bundle's full concept-id set and is what keeps this from
    over-firing: a bracketed token is only reported when it names a REAL concept
    of the bundle that the gate withheld. Models also write ``[1]``, ``[note]``,
    and markdown links, and none of those are provenance claims — they are
    dropped silently rather than counted as attacks.
    """
    admitted = set(admitted_ids)
    known = set(known_ids)
    cited = list(dict.fromkeys(CONCEPT_CITATION_RE.findall(answer)))
    return (
        [c for c in cited if c in admitted],
        [c for c in cited if c not in admitted and c in known],
    )
