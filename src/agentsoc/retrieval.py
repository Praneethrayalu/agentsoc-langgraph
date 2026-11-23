"""Chroma persistent retrieval with explicit CPU-only, stateless hashing embeddings."""

import chromadb
from sklearn.feature_extraction.text import HashingVectorizer


class AttackIndex:
    def __init__(self, path: str):
        self.client = chromadb.PersistentClient(path=path)
        self.collection = self.client.get_or_create_collection(
            "attack-techniques", metadata={"hnsw:space": "cosine"}
        )
        self.vectorizer = HashingVectorizer(
            n_features=2048, alternate_sign=False, norm="l2", stop_words="english", ngram_range=(1, 2)
        )

    def embed(self, texts: list[str]):
        return self.vectorizer.transform(texts).toarray().astype("float32").tolist()

    def load(self, documents: list[dict]):
        for start in range(0, len(documents), 80):
            batch = documents[start : start + 80]
            texts = [d["name"] + "\n" + d["text"] for d in batch]
            self.collection.upsert(
                ids=[d["id"] for d in batch],
                documents=texts,
                embeddings=self.embed(texts),
                metadatas=[{"name": d["name"], "url": d["url"]} for d in batch],
            )

    def search(self, query: str, limit: int = 3) -> list[dict]:
        if not self.collection.count():
            return []
        result = self.collection.query(
            query_embeddings=self.embed([query]), n_results=min(limit, self.collection.count())
        )
        return [
            {
                "technique_id": ident,
                "name": meta["name"],
                "url": meta["url"],
                "excerpt": text[:900],
                "distance": round(distance, 4),
            }
            for ident, meta, text, distance in zip(
                result["ids"][0], result["metadatas"][0], result["documents"][0], result["distances"][0]
            )
        ]
