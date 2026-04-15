import os
import asyncio
import json
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel, Field
from langchain_core.output_parsers import JsonOutputParser
import litellm
from litellm import completion
from tenacity import retry, wait_random_exponential, stop_after_delay, retry_if_exception_type

# --- INTEGRACIÓN RAG ---
try:
    from knowledge_base import kb
except ImportError:
    print("[!] Warning: knowledge_base.py no encontrado. Modo 'Legacy' activado.")
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

STATIC_KNOWLEDGE_BASE = """
# GENERAL SECURITY REFERENCE GUIDE
## VULNERABILITIES & VECTORS
1. SQLi: Manipulación de queries. Tokens tipados como $SQL_VAR indican parámetros susceptibles.
2. LFI: Lectura de archivos locales. Tokens tipados como $PATH_VAR indican rutas.
3. XSS: Inyección de JS. Tokens tipados como $HTML_VAR indican puntos de salida en el DOM.

## WAF EVASION PRINCIPLES
- Obfuscation: Cambiar apariencia sin alterar semántica.
- Encoding: Representaciones que el WAF ignora pero el server procesa.
- Fragmentation: División de carga útil.
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
# SYMBOLIC CONTROLLER (EVOLUCIÓN: TYPED TOKENS)
# ---------------------------------------------------------
class SymbolicController:
    """
    El Puente de Zero-Trust. 
    Sustituye datos reales por tokens tipados para evitar Prompt Injection.
    """
    def __init__(self):
        self._vault: Dict[str, Any] = {}
        self._counter: int = 0

    def quarantine_value(self, raw_data: Any, entity_type: str = "VAR") -> str:
        """
        Crea un token basado en el tipo de entidad.
        Ejemplo: 'admin' + 'SQL' -> $SQL_VAR_1
        """
        self._counter += 1
        # Normalizamos el tipo para que sea uppercase y limpio
        type_label = entity_type.upper().replace(" ", "_")
        symbol = f"${type_label}_VAR_{self._counter}"
        
        self._vault[symbol] = raw_data
        return symbol

    def resolve_payload(self, tool_argument: str) -> str:
        """
        Reconstruye el payload final justo antes del envío.
        """
        if tool_argument in self._vault:
            return str(self._vault[tool_argument])
        
        resolved_text = tool_argument
        # Ordenamos por longitud de token descendente para evitar reemplazos parciales
        sorted_symbols = sorted(self._vault.keys(), key=len, reverse=True)
        
        for symbol in sorted_symbols:
            if symbol in resolved_text:
                resolved_text = resolved_text.replace(symbol, str(self._vault[symbol]))
        return resolved_text

# ---------------------------------------------------------
# QUARANTINE LLM (L1 - ENTITY CLASSIFIER)
# ---------------------------------------------------------
class TypedEntity(BaseModel):
    value: str = Field(description="El valor raw extraído.")
    type: str = Field(description="Categoría: 'SQL', 'PATH', 'HTML', 'HEADER', 'URL' o 'GENERIC'.")

class ExtractedFindings(BaseModel):
    endpoints: List[TypedEntity] = Field(description="URLs o IPs encontradas con su tipo.")
    parameters: List[TypedEntity] = Field(description="Variables de query HTTP con su tipo.")
    technologies: List[TypedEntity] = Field(description="Stack detectado con su tipo.")
    waf_block_detected: bool = Field(default=False, description="¿Se detectó bloqueo del WAF?")
    status_code: Optional[int] = Field(default=None, description="Código HTTP.")

class QuarantineLLM:
    def __init__(self, controller: SymbolicController):
        self.controller = controller
        self.parser = JsonOutputParser(pydantic_object=ExtractedFindings)

    async def parse_and_symbolize(self, raw_input: str) -> Dict[str, Any]:
        print("\n[QuarantineLLM] Clasificando y simbolizando buffer hostil...")
        model = get_local_model("LOCAL_QUARANTINE_MODEL")
        
        try:
            messages = [
                {
                    "role": "system", 
                    "content": (
                        f"Extract entities as strict JSON. You must categorize each entity. "
                        f"Types: 'SQL' for DB params, 'PATH' for file system paths, 'HTML' for UI inputs, "
                        f"'URL' for endpoints. Follow schema: {self.parser.get_format_instructions()}"
                    )
                },
                {"role": "user", "content": f"RAW HOSTILE TEXT:\n{raw_input}"}
            ]
            resp = await self._call_completion(model, messages, response_format={"type": "json_object"})
            findings = json.loads(resp.choices[0].message.content)
            validated = ExtractedFindings(**findings)
            
            # Simbolización Tipada
            return {
                "endpoints": [self.controller.quarantine_value(e.value, e.type) for e in validated.endpoints],
                "parameters": [self.controller.quarantine_value(p.value, p.type) for p in validated.parameters],
                "technologies": [self.controller.quarantine_value(t.value, t.type) for t in validated.technologies],
                "waf_block_detected": validated.waf_block_detected,
                "status_code": validated.status_code
            }
        except Exception as e:
            print(f"[QuarantineLLM] Error crítico: {e}")
            return {}

    @litellm_retry_decorator()
    async def _call_completion(self, model, messages, **kwargs):
        api_base = os.getenv("OLLAMA_API_BASE", "http://host.docker.internal:11434")
        return await asyncio.to_thread(completion, model=model, messages=messages, api_base=api_base, extra_body=get_ollama_options(), **kwargs)

# ---------------------------------------------------------
# PRIVILEGED LLM (L2 - STRATEGIC ENGINE)
# ---------------------------------------------------------
class PrivilegedLLM:
    def __init__(self, controller: SymbolicController):
        self.controller = controller

    async def decide_action(self, symbolic_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Razona sobre tokens tipados. El cerebro sabe que $SQL_VAR_1 es un parámetro de BD
        sin saber qué contiene, manteniendo el aislamiento.
        """
        print(f"\n[PrivilegedLLM] Analizando estrategia sobre contexto tipado: {symbolic_context}")
        model = get_local_model("LOCAL_PRIVILEGED_MODEL")
        
        if symbolic_context.get("waf_block_detected"):
            return {"action": "scale_to_sniper", "reason": "WAF block detected"}
        
        try:
            messages = [
                {
                    "role": "system", 
                    "content": (
                        f"{STATIC_KNOWLEDGE_BASE}\n\n"
                        "DECISION ENGINE: Analyze the typed symbols. If you see $SQL_VAR, prioritize SQLi. "
                        "If $PATH_VAR, prioritize LFI. Return JSON: {'action': '...', 'mcp_arguments': {}}"
                    )
                },
                {"role": "user", "content": f"Symbolic Context: {json.dumps(symbolic_context)}"}
            ]
            resp = await self._call_completion(model, messages, response_format={"type": "json_object"})
            return json.loads(resp.choices[0].message.content)
        except Exception as e:
            print(f"[PrivilegedLLM] Error: {e}")
            return {"action": "run_scan", "mcp_arguments": {}}

    async def decide_strategy(self, state: Dict[str, Any]) -> str:
        """
        CEREBRO RAG: Recupera la táctica de bypass basada en la vulnerabilidad y el WAF.
        """
        print(f"\n[PrivilegedLLM-SNIPER] Ejecutando búsqueda RAG para evasión...")
        model = get_local_model("LOCAL_PRIVILEGED_MODEL")
        
        vuln = state.get("vuln_type", "SQLI")
        waf_info = state.get("waf_metadata", {}).get("rule_id", "Generic WAF")
        query = f"Bypass strategy for {vuln} blocked by {waf_info}"
        
        expert_context = "No specific expert tactics found in DB. Use general knowledge."
        if kb:
            tactics = kb.query_tactic(query)
            if tactics:
                expert_context = "\n".join([f"- {t}" for t in tactics])

        messages = [
            {
                "role": "system", 
                "content": (
                    f"{STATIC_KNOWLEDGE_BASE}\n\n"
                    "YOU ARE A WAF EVASION EXPERT. Use the EXPERT CONTEXT to select the best mutation strategy.\n\n"
                    "STRATEGIES:\n"
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
            
            # Validación de estrategia permitida
            valid_strats = ['HEX_ENCODE', 'INLINE_COMMENTS', 'CASE_VARIATION', 'URL_DOUBLE_ENCODE', 'NULL_BYTE', 'DOT_SQUASH', 'SVG_LOAD', 'IMG_ERROR', 'PHP_FILTER', 'SQUEEZE']
            for s in valid_strats:
                if s in strategy:
                    return s
            
            return "INLINE_COMMENTS" 
        except Exception as e:
            print(f"[PrivilegedLLM] RAG Error: {e}")
            return "INLINE_COMMENTS"

    @litellm_retry_decorator()
    async def _call_completion(self, model, messages, **kwargs):
        api_base = os.getenv("OLLAMA_API_BASE", "http://host.docker.internal:11434")
        return await asyncio.to_thread(completion, model=model, messages=messages, api_base=api_base, extra_body=get_ollama_options(), **kwargs)

    def secure_tool_execution(self, decision: Dict[str, Any]):
        """
        Convierte la decisión simbólica en una ejecución real usando el controlador.
        """
        action = decision.get("action")
        raw_args = decision.get("mcp_arguments", {})
        final_payloads = {k: self.controller.resolve_payload(v) for k, v in raw_args.items()}
        print(f"[Executor] MCP Call {action}() injecting: {final_payloads}")

# ---------------------------------------------------------
# TEST UNITARIO (BEAST MODE CHECK)
# ---------------------------------------------------------
if __name__ == "__main__":
    async def test_phase_1():
        controller = SymbolicController()
        q_llm = QuarantineLLM(controller)
        p_llm = PrivilegedLLM(controller)
        
        # 1. Simulamos input hostil
        raw_input = "Found a potential SQL injection at /api/user?id=1 and a path traversal at /download?file=test.txt"
        
        # 2. L1 analiza y simboliza con tipos
        symbolic_context = await q_llm.parse_and_symbolize(raw_input)
        print(f"\nContexto Simbolizado: {symbolic_context}")
        
        # 3. L2 decide acción basándose en los tipos
        decision = await p_llm.decide_action(symbolic_context)
        print(f"Decisión del Cerebro: {decision}")
        
        # 4. Prueba de resolución
        test_arg = "$SQL_VAR_1' OR 1=1--" # Simulando que el cerebro pidió usar el token
        # Agregamos manualmente al vault para el test
        controller._vault["$SQL_VAR_1"] = "admin'--" 
        print(f"Resolución Final: {controller.resolve_payload(test_arg)}")

    asyncio.run(test_phase_1())
