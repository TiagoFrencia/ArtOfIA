import os
import asyncio
from typing import TypedDict, List, Dict, Any, Union
from langgraph.graph import StateGraph, END

# Importaciones de los módulos evolucionados en Fase 2
from dual_llm_pattern import PrivilegedLLM, QuarantineLLM, SymbolicController
from reflector import Reflector

# Módulos de soporte
try:
    from mutators import arsenal 
    from planner import Planner
    from sniper import Sniper
except ImportError as e:
    print(f"[!] Warning: Módulos auxiliares no encontrados ({e}). Usando fallbacks.")

# --- ESQUEMA DE ESTADO "BEAST MODE 2.0" ---
class AgentState(TypedDict):
    # Misión y Target
    mission: str
    target_url: str
    
    # Payload y Vulnerabilidad
    current_payload: str
    vuln_type: str  # 'SQLI', 'LFI', 'XSS'
    
    # Control de Flujo
    iteration: int
    status: str # 'starting', 'success', 'blocked', 'failed', 'analyzed'
    last_action: str # 'MUTATE' o 'RUN_TOOL'
    
    # Datos de Análisis y Exfiltración
    exfiltrated_data: str
    tool_output: str # Almacena el stdout de sqlmap, nmap, etc.
    last_tool: str # Nombre de la herramienta ejecutada
    last_response_metadata: Dict[str, Any] 
    waf_metadata: Dict[str, Any] 
    failed_attempts_summary: List[Dict[str, Any]] 
    
    # Mapa Simbólico
    symbolic_map: List[str]

class ArtOfIAOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.max_iterations = 25
        
        # 1. Controladores y LLMs
        self.controller = SymbolicController()
        self.quarantine = QuarantineLLM(self.controller)
        self.brain = PrivilegedLLM(self.controller)
        
        # 2. Reflector Híbrido (Análisis HTTP + Stdout)
        self.reflector = Reflector(target_url=target_url)
        
        # Soporte
        try:
            self.planner = Planner() 
            self.sniper = Sniper()
        except:
            self.planner = None
            self.sniper = None

    async def planner_node(self, state: AgentState):
        """Coordinador inicial: Define el vector de ataque."""
        print(f"\n[*] [PLANNER] Iteración {state.get('iteration', 0)}. Trazando ruta de ataque...")
        
        if self.planner:
            result = await self.planner.execute(state)
        else:
            result = {"current_payload": "1' OR 1=1--", "vuln_type": "SQLI"}
            
        return {
            **result, 
            "iteration": state.get("iteration", 0) + 1,
            "status": "starting"
        }

    async def quarantine_node(self, state: AgentState):
        """L1: Aislamiento y Simbolización de la respuesta hostil."""
        print("[*] [QUARANTINE] Ejecutando aislamiento simbólico (L1)...")
        
        # Obtenemos el contenido real para analizar (de la última respuesta del reflector)
        raw_response = state.get("last_response_metadata", {}).get("last_content", "")
        if not raw_response:
            raw_response = f"Target URL: {state['target_url']}"

        symbolic_findings = await self.quarantine.parse_and_symbolize(raw_response)
        
        return {
            "waf_metadata": {
                "block_detected": symbolic_findings.get("waf_block_detected", False),
                "status_code": symbolic_findings.get("status_code"),
                "detected_tech": symbolic_findings.get("technologies", [])
            },
            "symbolic_map": symbolic_findings.get("parameters", []),
            "status": "analyzed"
        }

    async def strategy_node(self, state: AgentState):
        """
        Sustituye al antiguo Sniper Node.
        El Cerebro (L2) decide si usar una MUTACIÓN quirúrgica o una HERRAMIENTA profesional.
        """
        print(f"[*] [STRATEGY] Consultando al PrivilegedLLM sobre el vector {state.get('vuln_type')}...")
        
        # El cerebro analiza el contexto simbólico y decide la acción
        # Enviamos el contexto simbólico actual
        symbolic_context = {
            "parameters": state.get("symbolic_map", []),
            "waf_block_detected": state.get("waf_metadata", {}).get("block_detected", False),
            "status_code": state.get("waf_metadata", {}).get("status_code")
        }
        
        decision = await self.brain.decide_action(symbolic_context)
        
        # Si la decisión es MUTATE, aplicamos la mutación inmediatamente
        if decision.get("action") == "MUTATE":
            print(f"[+] [STRATEGY] Decisión: MUTATE. Aplicando bypass quirúrgico...")
            strategy_name = await self.brain.decide_strategy(state)
            try:
                mutated_payload = arsenal.mutate(
                    payload=state["current_payload"], 
                    vuln_type=state.get("vuln_type", "SQLI"), 
                    strategy=strategy_name
                )
                return {
                    "current_payload": mutated_payload,
                    "last_action": "MUTATE",
                    "status": "ready_to_test"
                }
            except Exception as e:
                print(f"[-] Error en mutación: {e}")
                return {"last_action": "MUTATE", "status": "ready_to_test"}
        
        # Si la decisión es RUN_TOOL, pasamos el control al ToolExecutor
        elif decision.get("action") == "RUN_TOOL":
            print(f"[+] [STRATEGY] Decisión: RUN_TOOL ({decision.get('tool')}).")
            return {
                "last_action": "RUN_TOOL",
                "last_tool": decision.get("tool"),
                "current_payload": decision.get("arguments"), # Guardamos los args como payload temporal
                "status": "ready_for_tool"
            }
        
        return {"status": "failed"}

    async def tool_executor_node(self, state: AgentState):
        """El Brazo Robótico: Ejecuta la herramienta en el contenedor ai-worker."""
        print(f"[*] [EXECUTOR] Lanzando herramienta {state.get('last_tool')} en sandbox...")
        
        # Llamamos al orquestador de ejecución del cerebro
        decision = {
            "action": "RUN_TOOL", 
            "tool": state.get("last_tool"), 
            "arguments": state.get("current_payload")
        }
        
        result = await self.brain.secure_tool_execution(decision)
        
        if result["status"] == "success":
            return {
                "tool_output": result.get("output", ""),
                "status": "tool_completed"
            }
        else:
            print(f"[-] Tool Error: {result.get('message')}")
            return {"status": "failed", "tool_output": result.get("message")}

    async def reflector_node(self, state: AgentState):
        """El Juez Híbrido: Analiza HTTP Response o Tool Output."""
        # El reflector ahora sabe si analizar un payload o una salida de herramienta
        # basándose en 'last_action'
        result = await self.reflector.execute(state)
        return result

    def build_graph(self):
        """Construcción del Grafo de Estado de LangGraph (Beast Mode 2.0)."""
        workflow = StateGraph(AgentState)
        
        # Añadir nodos
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("quarantine", self.quarantine_node)
        workflow.add_node("strategy", self.strategy_node)
        workflow.add_node("tool_executor", self.tool_executor_node)
        workflow.add_node("reflector", self.reflector_node)

        # --- FLUJO DE EJECUCIÓN ---
        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "reflector")
        
        # Ruteo Condicional desde Reflector
        workflow.add_conditional_edges(
            "reflector",
            lambda x: x["status"],
            {
                "success": END,
                "blocked": "quarantine",
                "failed": "quarantine",
                "tool_completed": "quarantine" # Analizar el resultado de la herramienta
            }
        )
        
        # El camino después de Quarantine siempre es la Estrategia
        workflow.add_edge("quarantine", "strategy")
        
        # Ruteo Condicional desde Strategy (Cerebro)
        workflow.add_conditional_edges(
            "strategy",
            lambda x: x["last_action"],
            {
                "MUTATE": "reflector",      # Si mutamos, probamos el payload directamente
                "RUN_TOOL": "tool_executor" # Si decidimos herramienta, vamos al ejecutor
            }
        )
        
        # Después de ejecutar la herramienta, vamos al reflector para validar el éxito
        workflow.add_edge("tool_executor", "reflector")

        return workflow.compile()

async def main():
    target = "http://testphp.vulnweb.com" 
    orchestrator = ArtOfIAOrchestrator(target_url=target)
    app = orchestrator.build_graph()
    
    print("\n" + "="*60)
    print(" ART OF IA v3.0 - BEAST MODE: PHASE 2 ACTIVE ")
    print(" [Strategic Brain] | [Professional Arsenal] | [Hybrid Reflector] ")
    print("="*60 + "\n")
    
    initial_state = {
        "mission": "Detectar y explotar vulnerabilidades críticas",
        "target_url": target,
        "current_payload": "1' OR 1=1--", 
        "vuln_type": "SQLI", 
        "exfiltrated_data": "",
        "iteration": 0,
        "status": "starting",
        "last_action": "MUTATE",
        "failed_attempts_summary": [],
        "last_response_metadata": {},
        "waf_metadata": {},
        "symbolic_map": [],
        "tool_output": ""
    }
    
    try:
        async for output in app.astream(initial_state):
            # El estado se actualiza automáticamente en el grafo
            pass
    except Exception as e:
        print(f"[!] Error en el ciclo de ejecución: {e}")

if __name__ == "__main__":
    asyncio.run(main())
