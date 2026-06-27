import re

from openai import OpenAI

from src.config import LLM_MODEL, LLM_TEMPERATURE, SYSTEM_PROMPT, USER_PROMPT_TEMPLATE

CITATION_RE = re.compile(r"\[([A-Za-z0-9._-]+__chunk\d{3})\]")


def generate(question: str, chunks: list[dict], client: OpenAI) -> str:
    """Build a cited answer from ``chunks`` using the configured LLM.

    The prompt instructs the model to embed chunk IDs inline as ``[chunk_id]``.
    Call ``parse_citations()`` on the returned string to extract those IDs.
    The Day 10 answer hook will extend this to sign the answer + chunk hashes
    into an attestation object.
    """
    context_block = "\n\n".join(
        f"[{c['chunk_id']}] (from: {c['title']})\n{c['text']}" for c in chunks
    )
    user_msg = USER_PROMPT_TEMPLATE.format(
        question=question, context_block=context_block
    )
    response = client.chat.completions.create(
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
    )
    return response.choices[0].message.content


def parse_citations(answer: str) -> list[str]:
    """Extract chunk IDs cited by the LLM in the form ``[doc_id__chunkNNN]``.

    Returns IDs in first-appearance order with duplicates removed. These are
    non-cryptographic citations — integrity is not verified here; that is the
    job of the Day 5–8 read hook.
    """
    return list(dict.fromkeys(CITATION_RE.findall(answer)))
