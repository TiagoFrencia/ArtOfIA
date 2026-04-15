import asyncio
import os
import json
from dual_llm_pattern import SymbolicController, PrivilegedLLM
from mutators import mutate_payload
from semantic_memory import SemanticMemory

# --- MOCK WAF LOG (ModSecurity Serial Format) ---
MOCK_WAF_LOG = """
--84ed0984-A--
[14/Apr/2026:18:00:00 +0000] 127.0.0.1 80 127.0.0.1 443
--84ed0984-B--
POST /vulnerable.php HTTP/1.1
Host: localhost
User-Agent: curl/7.81.0

--84ed0984-C--
user=1' OR '1'='1
--84ed0984-H--
Message: Access denied with code 403 (phase 2). Pattern match "' OR '1'='1" at ARGS:user. [file "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "542"] [id "942100"] [rev ""] [msg "SQL Injection Attack Detected via libmodsecurity"] [data "Matched Data: ' OR '1'='1 found within ARGS:user: 1' OR '1'='1"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.2"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/33"] [tag "PCI/6.5.1"]
Action: Intercepted (phase 2)
--84ed0984-Z--
"""

async def validate_local_intelligence():
    print("=== VALIDACION DE INTELIGENCIA LOCAL (Ollama + Mutators) ===")
    
    # 1. Test de Sniper
    print("\n[1/2] Testeando Sniper Node (Local LLM Strategy)...")
    controller = SymbolicController()
    p_llm = PrivilegedLLM(controller)
    
    original_payload = "1' OR '1'='1"
    
    try:
        # Esto llamará a Ollama (qwen2.5-coder:14b)
        strategy = await p_llm.generate_mutation_strategy(MOCK_WAF_LOG, original_payload)
        print(f"  > Estrategia detectada por LLM: {strategy}")
        
        mutated = mutate_payload(original_payload, strategy)
        print(f"  > Payload mutado (Final): {mutated}")
        
        if strategy and mutated != original_payload:
            print("  [SUCCESS] El Sniper local pudo proponer y aplicar una mutacion.")
        else:
            print("  [WARNING] La mutacion no cambio el payload o no hubo estrategia.")
            
    except Exception as e:
        print(f"  [ERROR] Fallo en la llamada al LLM local: {e}")

    # 2. Test de Memoria Semántica (Local Embeddings)
    print("\n[2/2] Testeando Memoria Semantica (sentence-transformers)...")
    try:
        memory = SemanticMemory()
        test_content = "Vectores de ataque detectados en ModSecurity CRS v3.3"
        memory.add_memory(test_content, {"type": "test"})
        
        results = memory.search_similar("ataques en modsecurity", limit=1)
        if results and results[0]['content'] == test_content:
            print(f"  [SUCCESS] Memoria semantica local recuperada: {results[0]['content']}")
            print(f"  [INFO] Similitud detectada: {results[0]['similarity']:.4f}")
        else:
            print("  [ERROR] No se pudo recuperar la memoria semantica local.")
            
    except Exception as e:
        print(f"  [ERROR] Fallo en la memoria semantica local: {e}")

if __name__ == "__main__":
    # Asegurémonos de que el entorno sea local
    os.environ["OLLAMA_API_BASE"] = "http://localhost:11434" # Para test fuera de host.docker.internal si corre local
    asyncio.run(validate_local_intelligence())
