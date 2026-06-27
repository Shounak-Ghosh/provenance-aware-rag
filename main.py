import logging
import os

from dotenv import load_dotenv
from openai import OpenAI
from sentence_transformers import SentenceTransformer

from src.config import EMBED_MODEL_NAME
from src.generate import generate, parse_citations
from src.ingest import fetch_corpus, ingest
from src.retrieve import retrieve
from src.store import get_collection

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)


def main() -> None:
    papers = fetch_corpus()
    logging.info("Corpus: %d papers loaded", len(papers))

    logging.info("Loading embedding model: %s", EMBED_MODEL_NAME)
    embed_model = SentenceTransformer(EMBED_MODEL_NAME)

    collection = get_collection()
    ingest(papers, collection, embed_model)

    openai_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    question = "What are the main techniques used to improve reasoning in large language models?"
    logging.info("QUERY: %s", question)

    chunks = retrieve(question, collection, embed_model, n_results=5)
    logging.info("Retrieved %d chunks:", len(chunks))
    for c in chunks:
        logging.info(
            "  chunk_id=%-35s  dist=%.4f  title=%s",
            c["chunk_id"],
            c["distance"],
            c["title"][:60],
        )

    answer = generate(question, chunks, openai_client)
    logging.info("ANSWER:\n%s", answer)

    cited = parse_citations(answer)
    logging.info("Cited chunk IDs: %s", cited)


if __name__ == "__main__":
    main()
