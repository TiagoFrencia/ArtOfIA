import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Any

class KnowledgeBase:
    def __init__(self, db_path="./chroma_db"):
        # Inicializamos la DB Vectorial local
        self.client = chromadb.PersistentClient(path=db_path)
        # Usamos un modelo de embeddings ligero y potente
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.collection = self.client.get_or_create_collection(
            name="waf_bypasses", 
            embedding_function=self.emb_fn
        )

    def add_tactic(self, tactic_id: str, content: str, metadata: Dict[str, Any]):
        """Añade una técnica de bypass a la memoria del agente."""
        self.collection.add(
            documents=[content],
            metadatas=[metadata],
            ids=[tactic_id]
        )

    def query_tactic(self, query_text: str, n_results: int = 2) -> List[str]:
        """Busca la técnica más parecida al problema actual."""
        results = self.collection.query(
            query_texts=[query_text], 
            n_results=n_results
        )
        # Retornamos los fragmentos de texto encontrados
        return results['documents'][0] if results['documents'] else []

# Singleton para el agente
kb = KnowledgeBase()
