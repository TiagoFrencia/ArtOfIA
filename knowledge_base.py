import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Any, Optional
import logging

# Configuración de logging para trazar las recuperaciones del RAG
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ArtOfIA-RAG")

class KnowledgeBase:
    """
    KnowledgeBase Expert Mode.
    No solo busca similitudes, sino que recupera 'Tácticas de Evasión' 
    estructuradas para alimentar la toma de decisiones del PrivilegedLLM.
    """
    def __init__(self, db_path="./chroma_db"):
        # Inicializamos la DB Vectorial local
        self.client = chromadb.PersistentClient(path=db_path)
        
        # Modelo de embeddings optimizado para lenguaje técnico/seguridad
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        # Colección optimizada para tácticas de bypass
        self.collection = self.client.get_or_create_collection(
            name="expert_waf_bypasses", 
            embedding_function=self.emb_fn
        )

    def add_expert_tactic(self, tactic_id: str, vuln_type: str, waf_type: str, 
                         technique: str, justification: str, implementation: str):
        """
        Añade una táctica estructurada al cerebro del agente.
        
        Args:
            tactic_id: ID único (ej: 'sqli_cloudflare_01')
            vuln_type: 'SQLI', 'LFI', 'XSS', 'RCE'
            waf_type: 'Cloudflare', 'ModSecurity', 'AWS', 'Generic'
            technique: Nombre de la técnica (ej: 'Double URL Encoding')
            justification: Por qué funciona esta técnica contra este WAF.
            implementation: Instrucciones exactas de cómo mutar el payload.
        """
        # Creamos un documento rico que combine la técnica y la justificación para el embedding
        document = f"VULN: {vuln_type} | WAF: {waf_type} | TECH: {technique} | DESC: {justification}"
        
        metadata = {
            "vuln_type": vuln_type.upper(),
            "waf_type": waf_type,
            "technique": technique,
            "implementation": implementation,
            "justification": justification
        }
        
        self.collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[tactic_id]
        )
        logger.info(f"[RAG] Táctica experta indexada: {tactic_id} ({technique})")

    def query_expert_tactic(self, query_text: str, vuln_filter: Optional[str] = None, n_results: int = 1) -> List[Dict[str, Any]]:
        """
        Busca la táctica más efectiva basada en el problema actual.
        Utiliza filtrado por metadatos para evitar que el RAG sugiera 
        técnicas de LFI cuando estamos atacando SQLi.
        """
        # Construimos el filtro de metadatos si se proporciona el tipo de vulnerabilidad
        where_filter = {}
        if vuln_filter:
            where_filter = {"vuln_type": vuln_filter.upper()}

        results = self.collection.query(
            query_texts=[query_text], 
            n_results=n_results,
            where=where_filter
        )
        
        # Procesamos los resultados para devolver objetos de táctica completos
        expert_tactics = []
        if results['documents'] and results['metadatas']:
            for meta in results['metadatas'][0]:
                expert_tactics.append({
                    "technique": meta.get("technique"),
                    "justification": meta.get("justification"),
                    "implementation": meta.get("implementation"),
                    "waf_target": meta.get("waf_type")
                })
        
        return expert_tactics

# Singleton para el agente
kb = KnowledgeBase()

# ---------------------------------------------------------
# SEEDING: CARGA DE CONOCIMIENTO INICIAL (Ejemplo de Modo Experto)
# ---------------------------------------------------------
def seed_expert_knowledge():
    """Carga tácticas base para que el agente no empiece de cero."""
    initial_tactics = [
        {
            "id": "sqli_cloudflare_01",
            "vuln": "SQLI",
            "waf": "Cloudflare",
            "tech": "HEX_ENCODE",
            "just": "Cloudflare often misses hexadecimal representations of keywords like SELECT or UNION.",
            "impl": "Convert the payload to hex format using 0x... or use the MySQL HEX() function."
        },
        {
            "id": "lfi_generic_01",
            "vuln": "LFI",
            "waf": "Generic",
            "tech": "DOT_SQUASH",
            "just": "Many filters remove '../' but not '....//', which collapses back to '../' after a single pass.",
            "impl": "Replace '../' with '....//' to bypass recursive filter cleaning."
        },
        {
            "id": "sqli_modsec_01",
            "vuln": "SQLI",
            "waf": "ModSecurity",
            "tech": "INLINE_COMMENTS",
            "just": "ModSecurity rules often look for 'SELECT' but not 'SEL/**/ECT'.",
            "impl": "Insert C-style comments /**/ inside SQL keywords."
        }
    ]
    
    for t in initial_tactics:
        kb.add_expert_tactic(
            tactic_id=t["id"], 
            vuln_type=t["vuln"], 
            waf_type=t["waf"], 
            technique=t["tech"], 
            justification=t["just"], 
            implementation=t["impl"]
        )
    logger.info("[RAG] Base de conocimientos experta cargada exitosamente.")

# Ejecutar seed al iniciar
seed_expert_knowledge()
