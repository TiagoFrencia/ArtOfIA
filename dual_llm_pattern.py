import os
import asyncio
import random
import time
import json
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, ValidationError
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
import litellm
from litellm import completion
from tenacity import retry, wait_random_exponential, stop_after_delay, retry_if_exception_type

# --- INTEGRACIÓN RAG (SPRINT 2) ---
try:
    from knowledge_base import kb
except ImportError:
    print("[!] Warning: knowledge_base.py no encontrado. El agente funcionará en modo 'Legacy' (sin RAG).")
    kb = None

os.environ['LITELLM_LOG'] = 'INFO'

def _int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return default

def get_ollama_options() -> Dict[str, int]:
    return {
        "num_gpu": _int_from_env("OLLAMA_NUM_GPU", 99),
        "num_ctx": _int_from_env("OLLAMA_NUM_CTX", 8192),
    }

def get_local_model(env_var: str, default: str = "ollama/qwen3.5:9b") -> str:
    return os.getenv(env_var, default)

# Base de conocimiento general (Sigue siendo útil para Prompt Caching)
STATIC_KNOWLEDGE_BASE = """
# GENERAL SECURITY REFERENCE GUIDE
Este documento proporciona el marco general de ataque. Las tácticas específicas se recuperan dinámicamente vía RAG.

## VULNERABILITIES & VECTORS
1. SQLi: Manipulación de queries mediante inyección de caracteres especiales.
2. LFI: Lectura de archivos locales mediante rutas relativas o wrappers (php://filter).
3. XSS: Ejecución de JS en el cliente mediante tags maliciosos o eventos.

## WAF EVASION PRINCIPLES
- Obfuscation: Cambiar la apariencia del payload sin alterar la semántica.
- Encoding: Usar representaciones que el WAF no decodifique pero el servidor sí.
- Fragmentation: Dividir la carga útil para evadir firmas de regex.
"""

# ---------------------------------------------------------
# LLM RETRY LOGIC
# ---------------------------------------------------------
def litellm_retry_decorator():
    return retry(
        wait=wait_random_exponential(multiplier=1, max=300),
        stop=stop_after_delay(600),
        retry=retry_if_exception_type((litellm.RateLimitError, litellm.ServiceUnavailableError)),
        reraise=True
    )

# ---------------------------------------------------------
# SYMBOLIC CONTROLLER (ZERO-TRUST)
# ---------------------------------------------------------
class SymbolicController:
    def __init__(self):
        self._vault: Dict[str, Any] = {}
        self._counter: int = 0

    def quarantine_value(self, raw_data: Any) -> str:
        self._counter += 1
        symbol = f"$VAR_{self._counter}"
        self._vault[symbol] = raw_data
        return symbol

    def resolve_payload(self, tool_argument: str) -> str:
        if tool_argument in self._vault:
            return str(self._vault[tool_argument])
        resolved_text = tool_argument
        for symbol, raw_value in self._vault.items():
            if symbol in resolved_text:
                resolved_text = resolved_text.replace(symbol, str(raw_value))
        return resolved_text

# ---------------------------------------------------------
# QUARANTINE LLM (L1)
# ---------------------------------------------------------
class ExtractedFindings(BaseModel):
    endpoints: List[str] = Field(description="URLs o IPs encontradas.")
    parameters: List[str] = Field(description="Variables de query HTTP.")
    technologies: List[str] = Field(description="Stack detectado.")
    waf_block_detected: bool = Field(default=False, description="¿Se detectó bloqueo?")
    status_code: Optional[int] = Field(default=None, description="Código HTTP.")

class QuarantineLLM:
    def __init__(self, controller: SymbolicController):
        self.controller = controller
        self.parser = JsonOutputParser(pydantic_object=ExtractedFindings)

    async def parse_and_symbolize(self, raw_input: str) -> Dict[str, Any]:
        print("\n[QuarantineLLM] Analizando buffer hostil...")
        model = get_local_model("LOCAL_QUARANTINE_MODEL")
        
        try:
            messages = [
                {"role": "system", "content": f"Extract entities as strict JSON. Follow schema: {self.parser.get_format_instructions()}"},
                {"role": "user", "content": f"RAW HOSTILE TEXT:\n{raw_input}"}
            ]
            resp = await self._call_completion(model, messages, response_format={"type": "json_object"})
            findings = json.loads(resp.choices[0].message.content)
            validated = ExtractedFindings(**findings)
            
            # Simbolización
            return {
                "endpoints": [self.controller.quarantine_value(ep) for ep in validated.endpoints],
                "parameters": [self.controller.quarantine_value(p) for p in validated.parameters],
                "technologies": [self.controller.quarantine_value(t) for t in validated.technologies],
                "waf_block_detected": validated.waf_block_detected,
                "status_code": validated.status_code
            }
        except Exception as e:
            print(f"[QuarantineLLM] Error: {e}")
            return {}

    @litellm_retry_decorator()
    async def _call_completion(self, model, messages, **kwargs):
        api_base = os.getenv("OLLAMA_API_BASE", "http://host.docker.internal:11434")
        return await asyncio.to_thread(completion, model=model, messages=messages, api_base=api_base, extra_body=get_ollama_options(), **kwargs)

# ---------------------------------------------------------
# PRIVILEGED LLM (L2 - ACTION ENGINE WITH RAG)
# ---------------------------------------------------------
class PrivilegedLLM:
    def __init__(self, controller: SymbolicController):
        self.controller = controller

    async def decide_action(self, symbolic_context: Dict[str, Any]) -> Dict[str, Any]:
        print(f"\n[PrivilegedLLM] Razonando sobre contexto seguro: {symbolic_context}")
        model = get_local_model("LOCAL_PRIVILEGED_MODEL")
        
        if symbolic_context.get("waf_block_detected"):
            return {"action": "scale_to_sniper", "reason": "WAF block detected"}
        
        try:
            messages = [
                {"role": "system", "content": STATIC_KNOWLEDGE_BASE + "\n\nDecide the next action based on endpoints. Return JSON: {'action': '...', 'mcp_arguments': {}}"},
                {"role": "user", "content": f"Context: {json.dumps(symbolic_context)}"}
            ]
            resp = await self._call_completion(model, messages, response_format={"type": "json_object"})
            return json.loads(resp.choices[0].message.content)
        except Exception as e:
            print(f"[PrivilegedLLM] Error: {e}")
            return {"action": "run_scan", "mcp_arguments": {}}

    async def decide_strategy(self, state: Dict[str, Any]) -> str:
        """
        CEREBRO RAG: Consulta la Vector DB para elegir la mejor mutación.
        """
        print(f"\n[PrivilegedLLM-SNIPER] Consultando Base de Conocimiento Vectorial...")
        model = get_local_model("LOCAL_PRIVILEGED_MODEL")
        
        # 1. Construir Query de Búsqueda
        vuln = state.get("vuln_type", "SQLI")
        waf_info = state.get("waf_metadata", {}).get("rule_id", "Generic WAF")
        query = f"Bypass strategy for {vuln} blocked by {waf_info}"
        
        # 2. Recuperar Tácticas del RAG
        expert_context = "No specific expert tactics found in DB. Use general knowledge."
        if kb:
            tactics = kb.query_tactic(query)
            if tactics:
                expert_context = "\n".join([f"- {t}" for t in tactics])

        # 3. Prompt Refinado con Conocimiento Recuperado
        messages = [
            {
                "role": "system", 
                "content": (
                    f"{STATIC_KNOWLEDGE_BASE}\n\n"
                    "YOU ARE A WAF EVASION EXPERT. Use the provided EXPERT CONTEXT to select the most effective mutation strategy.\n\n"
                    "AVAILABLE STRATEGIES:\n"
                    "SQLI: ['HEX_ENCODE', 'INLINE_COMMENTS', 'CASE_VARIATION', 'URL_DOUBLE_ENCODE', 'NULL_BYTE']\n"
                    "LFI: ['DOT_SQUASH', 'NULL_BYTE', 'PHP_FILTER', 'UTF_ENCODE']\n"
                    "XSS: ['SVG_LOAD', 'IMG_ERROR', 'SQUEEZE', 'SENSITIVE_CASE']\n\n"
                    "Return ONLY the strategy name in uppercase."
                )
            },
            {
                "role": "user", 
                "content": f"QUERY: {query}\n\nEXPERT CONTEXT:\n{expert_context}"
            }
        ]
        
        try:
            resp = await self._call_completion(model, messages)
            strategy = resp.choices[0].message.content.strip().upper()
            
            # Limpieza de respuesta (quitar puntos o frases)
            for s in ['HEX_ENCODE', 'INLINE_COMMENTS', 'CASE_VARIATION', 'URL_DOUBLE_ENCODE', 'NULL_BYTE', 'DOT_SQUASH', 'SVG_LOAD', 'IMG_ERROR', 'PHP_FILTER']:
                if s in strategy:
                    return s
            
            return "INLINE_COMMENTS" # Fallback
        except Exception as e:
            print(f"[PrivilegedLLM] RAG Error: {e}")
            return "INLINE_COMMENTS"

    @litellm_retry_decorator()
    async def _call_completion(self, model, messages, **kwargs):
        api_base = os.getenv("OLLAMA_API_BASE", "http://host.docker.internal:11434")
        return await asyncio.to_thread(completion, model=model, messages=messages, api_base=api_base, extra_body=get_ollama_options(), **kwargs)

    def secure_tool_execution(self, decision: Dict[str, Any]):
        action = decision["action"]
        raw_args = decision["mcp_arguments"]
        final_payloads = {k: self.controller.resolve_payload(v) for k, v in raw_args.items()}
        print(f"[Executor] MCP Call {action}() injecting: {final_payloads}")

# ---------------------------------------------------------
# DEMO RUN
# ---------------------------------------------------------
if __name__ == "__main__":
    # Para probar el RAG localmente
    controller = SymbolicController()
    p_llm = PrivilegedLLM(controller)
    
    # Simulamos un estado donde el WAF bloqueó un SQLi
    test_state = {
        "vuln_type": "SQLI",
        "waf_metadata": {"rule_id": "ModSecurity 942100"},
        "current_payload": "UNION SELECT 1,2,3--"
    }
    
    async def test():
        strat = await p_llm.decide_strategy(test_state)
        print(f"\n[TEST] Estrategia elegida por RAG: {strat}")
    
    asyncio.run(test())
