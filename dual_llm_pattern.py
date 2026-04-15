import os
import asyncio
import json
import docker
import logging
from typing import Dict, Any, Optional, List, Tuple, Union
from pydantic import BaseModel, Field
from langchain_core.output_parsers import JsonOutputParser
import litellm
from litellm import completion
from tenacity import retry, wait_random_exponential, stop_after_delay, retry_if_exception_type

# --- INTEGRACIÓN RAG Y POLYMORPHIC BRIDGE ---
try:
    from knowledge_base import kb
except ImportError:
    print("[!] Warning: knowledge_base.py no encontrado. Modo 'Legacy' activado.")
    kb = None

try:
    from polymorphic_bridge import poly_bridge
except ImportError:
    print("[!] Warning: polymorphic_bridge.py no encontrado. Modo POLYMORPH deshabilitado.")
    poly_bridge = None

# --- CONFIGURACIÓN DE LOGGING ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ArtOfIA-Core")

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

# --- BASE DE CONOCIMIENTOS ACTUALIZADA (V3.0 - POLYMORPHIC) ---
STATIC_KNOWLEDGE_BASE = """
# GENERAL SECURITY REFERENCE GUIDE (V3.0)
## VULNERABILITIES & VECTORS
1. SQLi: Manipulación de queries. Tokens tipados como $SQL_VAR indican parámetros susceptibles.
2. LFI: Lectura de archivos locales. Tokens tipados como $PATH_VAR indican rutas.
3. XSS: Inyección de JS. Tokens tipados como $HTML_VAR indican puntos de salida en el DOM.

## TOOLSET CAPABILITIES (ai-worker)
- nmap: Port scanning and service detection.
- sqlmap: Automated SQL injection and database dumping.
- commix: Automated OS command injection.
- dirsearch/gobuster/ffuf: Directory and file brute-forcing.

## POLYMORPHIC ENCODERS (The Bridge)
- URL_ENCODE: Basic % encoding.
- DOUBLE_URL_ENCODE: Two layers of % encoding (Bypasses simple decoders).
- HEX_ENCODE: \\xXX format (Effective against regex-based WAFs).
- BASE64_ENCODE: Binary-to-text (For specific data channels).
- UNICODE_ESCAPE: \\uXXXX format (Confuses character normalization).
- NULL_BYTE: Inject \\x00 (Cuts string reading in backends).
- CASE_SQUASH: AlTeRnAtInG cAsE (Evades simple keyword filters like 'SELECT').

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
# SYMBOLIC CONTROLLER (Zero-Trust Bridge)
# ---------------------------------------------------------
class SymbolicController:
    def __init__(self):
        self._vault: Dict[str, Any] = {}
        self._counter: int = 0

    def quarantine_value(self, raw_data: Any, entity_type: str = "VAR") -> str:
        self._counter += 1
        type_label = entity_type.upper().replace(" ", "_")
        symbol = f"${type_label}_VAR_{self._counter}"
        self._vault[symbol] = raw_data
        return symbol

    def resolve_payload(self, tool_argument: str) -> str:
        if not tool_argument: return ""
        resolved_text = tool_argument
        sorted_symbols = sorted(self._vault.keys(), key=len, reverse=True)
        for symbol in sorted_symbols:
            if symbol in resolved_text:
                resolved_text = resolved_text.replace(symbol, str(self._vault[symbol]))
        return resolved_text

# ---------------------------------------------------------
# TOOL EXECUTOR (The Robotic Arm)
# ---------------------------------------------------------
class ToolExecutor:
    def __init__(self, container_name: str = "ai-worker"):
        try:
            self.client = docker.from_env()
            self.container_name = container_name
        except Exception as e:
            logger.error(f"Docker connection failed: {e}")
            self.client = None

        self.allowed_tools = {
            "nmap": {"binary": "nmap", "critical_flags": []},
            "sqlmap": {"binary": "sqlmap", "critical_flags": ["--os-shell"]},
            "commix": {"binary": "commix", "critical_flags": []},
            "dirsearch": {"binary": "dirsearch", "critical_flags": []},
            "gobuster": {"binary": "gobuster", "critical_flags": []},
            "ffuf": {"binary": "ffuf", "critical_flags": []},
        }

    def execute(self, tool: str, arguments: str, symbol_map: SymbolicController) -> Dict[str, Any]:
        if not self.client:
            return {"status": "error", "message": "Docker client not initialized"}
        
        resolved_args = symbol_map.resolve_payload(arguments)
        
        if tool not in self.allowed_tools:
            return {"status": "error", "message": f"Tool {tool} not in whitelist"}
        
        if any(char in resolved_args for char in [';', '&&', '||', '`']):
            return {"status": "error", "message": "Command injection detected in arguments"}

        try:
            container = self.client.containers.get(self.container_name)
            binary = self.allowed_tools[tool]["binary"]
            full_command = f"{binary} {resolved_args}"
            
            logger.info(f"[ToolExecutor] Running: {full_command}")
            exit_code, output = container.exec_run(cmd=full_command, user="root")
            
            output_text = output.decode('utf-8')
            return {
                "status": "success" if exit_code == 0 else "completed_with_errors",
                "exit_code": exit_code,
                "output": self._sanitize_output(output_text),
                "command": full_command
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _sanitize_output(self, text: str) -> str:
        lines = text.splitlines()
        filtered = [l for l in lines if not l.startswith('[***]')]
        final = "\n".join(filtered)
        return final[:4000] + "... [Truncated]" if len(final) > 4000 else final

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
        self.executor = ToolExecutor()

    async def decide_action(self, symbolic_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        BEAST MODE 3.0: El cerebro elige entre MUTATE, RUN_TOOL o POLYMORPH.
        """
        print(f"\n[PrivilegedLLM] Analizando estrategia sobre contexto tipado...")
        model = get_local_model("LOCAL_PRIVILEGED_MODEL")
        
        try:
            messages = [
                {
                    "role": "system", 
                    "content": (
                        f"{STATIC_KNOWLEDGE_BASE}\n\n"
                        "DECISION ENGINE: You are the brain. Analyze typed symbols.\n"
                        "IF you see $SQL_VAR and want a surgical strike -> ACTION: 'MUTATE'.\n"
                        "IF you want an exhaustive scan or DB dump -> ACTION: 'RUN_TOOL'.\n"
                        "IF you are blocked by WAF and need an encoding chain -> ACTION: 'POLYMORPH'.\n\n"
                        "JSON FORMATS:\n"
                        "- For MUTATE: {'action': 'MUTATE', 'payload_type': 'SQLI', 'target_symbol': '$SQL_VAR_1'}\n"
                        "- For RUN_TOOL: {'action': 'RUN_TOOL', 'tool': 'sqlmap', 'arguments': '-u $URL_1 -p $SQL_VAR_1 --batch'}\n"
                        "- For POLYMORPH: {'action': 'POLYMORPH', 'chain': ['CASE_SQUASH', 'DOUBLE_URL_ENCODE'], 'target_symbol': '$SQL_VAR_1'}\n"
                        "Strict JSON output only."
                    )
                },
                {"role": "user", "content": f"Symbolic Context: {json.dumps(symbolic_context)}"}
            ]
            resp = await self._call_completion(model, messages, response_format={"type": "json_object"})
            return json.loads(resp.choices[0].message.content)
        except Exception as e:
            print(f"[PrivilegedLLM] Error: {e}")
            return {"action": "MUTATE", "payload_type": "GENERIC", "target_symbol": "$VAR_1"}

    async def decide_strategy(self, state: Dict[str, Any]) -> Union[str, List[str]]:
        """
        RAG-Driven Mutation/Polymorphism. 
        Retorna un string si es MUTATE o una lista de encoders si es POLYMORPH.
        """
        print(f"\n[PrivilegedLLM-SNIPER] Ejecutando búsqueda RAG para evasión...")
        model = get_local_model("LOCAL_PRIVILEGED_MODEL")
        
        last_action = state.get("last_action", "MUTATE")
        vuln = state.get("vuln_type", "SQLI")
        waf_info = state.get("waf_metadata", {}).get("rule_id", "Generic WAF")
        query = f"Best evasion strategy for {vuln} blocked by {waf_info}"
        
        expert_context = "No specific expert tactics found in DB. Use general knowledge."
        if kb:
            tactics = kb.query_expert_tactic(query, vuln_filter=vuln)
            if tactics: 
                expert_context = "\n".join([f"TECH: {t['technique']} | IMPL: {t['implementation']}" for t in tactics])

        messages = [
            {
                "role": "system", 
                "content": (
                    f"{STATIC_KNOWLEDGE_BASE}\n\n"
                    f"YOU ARE A WAF EVASION EXPERT. Select the best mutation strategy based on EXPERT CONTEXT.\n"
                    f"If last_action is 'MUTATE' -> Return ONLY the strategy name (e.g., 'HEX_ENCODE').\n"
                    f"If last_action is 'POLYMORPH' -> Return a JSON list of encoders (e.g., ['CASE_SQUASH', 'URL_ENCODE']).\n"
                    f"Return ONLY the result, no conversational text."
                )
            },
            {
                "role": "user", 
                "content": f"ACTION: {last_action}\nQUERY: {query}\nEXPERT CONTEXT:\n{expert_context}"
            }
        ]
        
        try:
            resp = await self._call_completion(model, messages)
            content = resp.choices[0].message.content.strip()
            
            if last_action == "POLYMORPH":
                if "[" in content: return json.loads(content)
                return [content.upper()]
            
            return content.upper()
        except Exception as e:
            print(f"[PrivilegedLLM] RAG Error: {e}")
            return "INLINE_COMMENTS" if last_action == "MUTATE" else ["URL_ENCODE"]

    @litellm_retry_decorator()
    async def _call_completion(self, model, messages, **kwargs):
        api_base = os.getenv("OLLAMA_API_BASE", "http://host.docker.internal:11434")
        return await asyncio.to_thread(completion, model=model, messages=messages, api_base=api_base, extra_body=get_ollama_options(), **kwargs)

    async def secure_tool_execution(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """
        ORQUESTADOR FINAL: Traduce la decisión del cerebro en ejecución real.
        Soporta RUN_TOOL, MUTATE y POLYMORPH.
        """
        action = decision.get("action")
        
        if action == "RUN_TOOL":
            tool = decision.get("tool")
            args = decision.get("arguments")
            print(f"[Executor] Launching Professional Tool: {tool}")
            return self.executor.execute(tool, args, self.controller)
        
        elif action == "POLYMORPH":
            chain = decision.get("chain", [])
            target_symbol = decision.get("target_symbol")
            print(f"[Executor] Applying Polymorphic Chain: {chain} to {target_symbol}")
            
            raw_payload = self.controller.resolve_payload(target_symbol)
            if poly_bridge:
                final_payload = poly_bridge.apply_chain(raw_payload, chain)
                return {
                    "status": "success", 
                    "action": "POLYMORPH", 
                    "final_payload": final_payload,
                    "chain_applied": chain
                }
            return {"status": "error", "message": "PolyBridge not initialized"}
        
        elif action == "MUTATE":
            print(f"[Executor] Performing surgical mutation on {decision.get('target_symbol')}")
            return {"status": "redirect", "message": "Proceed to SNIPER for mutation"}
        
        return {"status": "error", "message": "Invalid action decided by LLM"}

# ---------------------------------------------------------
# TEST UNITARIO (BEAST MODE CHECK)
# ---------------------------------------------------------
if __name__ == "__main__":
    async def test_beast_mode():
        controller = SymbolicController()
        q_llm = QuarantineLLM(controller)
        p_llm = PrivilegedLLM(controller)
        
        raw_input = "Found a potential SQL injection at http://target.com/api/user?id=1"
        symbolic_context = await q_llm.parse_and_symbolize(raw_input)
        print(f"\nContexto Simbolizado: {symbolic_context}")
        
        decision = await p_llm.decide_action(symbolic_context)
        print(f"Decisión del Cerebro: {decision}")
        
        result = await p_llm.secure_tool_execution(decision)
        print(f"Resultado de Ejecución: {result}")

    asyncio.run(test_beast_mode())
