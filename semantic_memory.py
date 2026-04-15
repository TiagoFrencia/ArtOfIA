import os
import json
import psycopg2
from psycopg2.extras import execute_values
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional

class SemanticMemory:
    """
    Controlador de Memoria Semántica para el Ralph Loop.
    Utiliza pgvector para almacenar y recuperar playbooks y hallazgos.
    """
    def __init__(self):
        self.host = os.getenv("PGHOST", "localhost")
        self.port = os.getenv("PGPORT", "5432")
        self.dbname = os.getenv("PGDATABASE", "art_of_ia")
        self.user = os.getenv("PGUSER", "postgres")
        self.password = os.getenv("PGPASSWORD", "secretpassword")
        self.encoder_model = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        self.encoder = SentenceTransformer(self.encoder_model)
        self.conn = None
        self._initialize_db()

    def _get_connection(self):
        if self.conn is None or self.conn.closed:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password
            )
            register_vector(self.conn)
        return self.conn

    def _initialize_db(self):
        """Crea la tabla de memoria y la extensión pgvector si no existen."""
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS semantic_memory (
                        id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
                        content text NOT NULL,
                        metadata jsonb,
                        embedding vector(384),
                        created_at timestamp DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # Índice HNSW para búsqueda rápida de similitud de coseno
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memory_embedding ON semantic_memory 
                    USING hnsw (embedding vector_cosine_ops)
                """)
            conn.commit()
            print("[SemanticMemory] Base de datos inicializada correctamente.")
        except Exception as e:
            print(f"[SemanticMemory] Error al inicializar DB: {e}")

    def add_memory(self, content: str, metadata: Optional[Dict[str, Any]] = None):
        """Vectoriza y guarda un nuevo fragmento de memoria localmente."""
        try:
            # Obtener embeddings locales usando sentence-transformers
            vector = self.encoder.encode([content])[0].tolist()

            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO semantic_memory (content, metadata, embedding) VALUES (%s, %s, %s)",
                    (content, json.dumps(metadata) if metadata else None, vector)
                )
            conn.commit()
            print(f"[SemanticMemory] Memoria física añadida (Local): {content[:50]}...")
        except Exception as e:
            print(f"[SemanticMemory] Error al añadir memoria: {e}")


    def search_similar(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Busca fragmentos similares en la memoria usando similitud de coseno local."""
        try:
            vector = self.encoder.encode([query])[0].tolist()

            conn = self._get_connection()
            results = []
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT content, metadata, 1 - (embedding <=> %s) AS similarity
                    FROM semantic_memory
                    ORDER BY embedding <=> %s
                    LIMIT %s
                """, (vector, vector, limit))
                for row in cur.fetchall():
                    results.append({
                        "content": row[0],
                        "metadata": row[1],
                        "similarity": row[2]
                    })
            return results
        except Exception as e:
            print(f"[SemanticMemory] Error al buscar en memoria: {e}")
            return []

if __name__ == "__main__":
    # Prueba rápida local
    mem = SemanticMemory()
    mem.add_memory("El servidor nmap detectó el puerto 80 abierto en 192.168.1.10", {"step": "recon"})
    print("Resultados similares:", mem.search_similar("cuáles son los puertos abiertos?"))
