import chromadb
from functools import lru_cache
from pathlib import Path
from sentence_transformers import SentenceTransformer


DEFAULT_MODEL = "all-MiniLM-L6-v2"
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "chroma_db"


@lru_cache(maxsize=2)
def _load_embedding_model(model_name):
    return SentenceTransformer(model_name)


@lru_cache(maxsize=8)
def _load_collection(db_path, collection_name):
    client = chromadb.PersistentClient(path=db_path)
    return client.get_collection(collection_name)


class Retriever:
    def __init__(self, db_path=None, collection_name="threat_intel", model_name=DEFAULT_MODEL):
        """Initialize Threat Intelligence Retriever"""
        if db_path is None:
            db_path = DEFAULT_DB_PATH

        self.db_path = str(Path(db_path).resolve())
        self.model = _load_embedding_model(model_name)
        self.collection = _load_collection(self.db_path, collection_name)
    
    def search(self, query, n_results=3, where=None):
        """Search threat intelligence database"""
        query_embedding = self.model.encode([query]).tolist()
        query_args = dict(
            query_embeddings=query_embedding,
            n_results=n_results,
        )
        if where:
            query_args["where"] = where
        return self.collection.query(**query_args)

    def search_batch(self, queries, n_results=3, where=None):
        """Embed and retrieve multiple behavior queries in a single batch."""
        if not queries:
            return {"documents": [], "metadatas": [], "distances": [], "ids": []}
        query_embeddings = self.model.encode(list(queries), batch_size=32).tolist()
        query_args = dict(query_embeddings=query_embeddings, n_results=n_results)
        if where:
            query_args["where"] = where
        return self.collection.query(**query_args)
    
    def pretty_print(self, results):
        """Pretty print search results"""
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        
        for i, (doc, meta) in enumerate(zip(docs, metas)):
            print(f"\n===== RESULT {i+1} =====")
            print(f"Type: {meta.get('type')}")
            print(doc)


if __name__ == "__main__":
    retriever = Retriever()
    while True:
        query = input("\nEnter query: ")

        if query.lower() in ["exit", "quit"]:
            break

        results = retriever.search(query)
        retriever.pretty_print(results)
