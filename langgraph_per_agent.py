import asyncio
import uuid
import random
import json
import os
import subprocess
import operator
from typing import List, Dict, Any, TypedDict, Annotated, Literal, Optional
from langgraph.graph import StateGraph, END, START
from planner import Planner, AttackNode, NodeType, NodeStatus

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- EXTERNAL INFRASTRUCTURE ---

class ExternalStateStore:
    """Simula PostgreSQL o progress.txt para el Bucle de Ralph."""
    def __init__(self, filename="STATE_PLAN.json"):
        self.filename = os.path.join(SCRIPT_DIR, filename)

    def dump_state(self, state: dict) -> None:
        with open(self.filename, 'w') as f:
            json.dump(state, f, indent=4)

    def load_state(self) -> Optional[dict]:
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                return json.load(f)
        return None

def load_prd() -> dict:
    """Carga la misión estricta para el agente."""
    prd_path = os.path.join(SCRIPT_DIR, "prd.json")
    if os.path.exists(prd_path):
        with open(prd_path, "r", encoding="utf-8") as f:
            return json.load(f)
    # Fallback default
    return {
        "mission": "Realizar un reconocimiento: hostname, interfaces. Guardar en proof.txt.",
        "required_proofs": ["proof.txt"],
        "promise_tag": "<promise>COMPLETE</promise>"
    }

# --- ESTRUCTURA DE ESTADO (LangGraph State) ---
class AgentState(TypedDict):
    trace_id: str
    mission: str
    required_proofs: List[str]
    
    # Graph Topology Storage
    graph_data: Dict[str, Any]
    
    pending_actions: List[Dict[str, Any]]
    completed_actions: Annotated[List[Dict[str, Any]], operator.add]
    
    recon_data: str # Para acumular la evidencia de sistema
    
    tool_calls_count: int
    current_cost: float
    causal_chain: Annotated[List[str], operator.add]
    
    is_aborted: bool
    is_completed: bool

# --- NODOS DEL SISTEMA P-E-R ---

async def quarantine_node(state: AgentState) -> dict:
    # Aísla la entrada, verifica que conocemos qué buscar
    return {}

async def planner_node(state: AgentState) -> dict:
    """[PLANIFICADOR PoG] Hidrata y Edita dinámicamente el DAG."""
    print("\n[Planner] Resolviendo estado del DAG de ataque...")
    
    planner = Planner()
    if state.get("graph_data"):
        planner.from_dict(state["graph_data"])
        
    # Sincronizamos la ejecución real con el grafo topológico
    for comp in state["completed_actions"]:
        if comp["id"] in planner.nodes:
            planner.update_node(comp["id"], {"status": NodeStatus.COMPLETED})
            
    causal_update = []
    if not planner.nodes:
        print("[Planner] Instanciando nodos base (LLM Predictor evalúa en background)...")
        # Formulamos ataque inicial evaluando TDA en vivo
        n1 = AttackNode(id="n1", type=NodeType.RECONNAISSANCE, action="bash", 
                        params={"command": "echo '=== hostname ===' && hostname && echo '=== whoami ===' && whoami"}, confidence=0.8)
        n2 = AttackNode(id="n2", type=NodeType.RECONNAISSANCE, action="bash", 
                        params={"command": "echo '=== interfaces ===' && (ipconfig 2>/dev/null || ip addr 2>/dev/null)"}, confidence=0.8)
        n3 = AttackNode(id="n3", type=NodeType.EXECUTION, action="write_proof", 
                        params={"filename": state["required_proofs"][0]}, confidence=0.9)
                        
        planner.add_node(n1)
        planner.add_node(n2, prerequisites=["n1"])
        planner.add_node(n3, prerequisites=["n2"])
        causal_update.append("Planificador: Grafo base creado, dinámicas EGATS calculadas.")
    else:
        causal_update.append("Planificador: Analizando estado y procediendo a bifurcaciones.")

    pruned = planner.prune_low_confidence_branches(threshold=0.3)
    if pruned:
        print(f"[Planner] Nodos DEPRECADOS por bajo desempeño (EGATS): {pruned}")
        
    ready_actions = planner.extract_ready_actions()
    
    pending = list(state["pending_actions"]) # Inmutable copy
    # Prevenir encolamiento duplicado
    for act in ready_actions:
        if not any(p["id"] == act["id"] for p in pending):
            pending.append(act)

    return {
        "graph_data": planner.to_dict(),
        "pending_actions": pending,
        "causal_chain": causal_update
    }

async def executor_node(state: AgentState) -> dict:
    """[EJECUTOR] Desempaca herramientas y las ejecuta realmente."""
    if not state["pending_actions"]: return {}
    
    pending = list(state["pending_actions"])
    current_action = pending.pop(0)
    
    action_type = current_action['action']
    params = current_action['params']
    
    print(f"\n[Executor] Ejecutando: {action_type}")
    
    # Acumuladores de estado delta
    new_recon_data = state["recon_data"]
    causal_updates = []
    
    if action_type == "bash":
        cmd = params.get("command", "")
        print(f"  $ {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            new_recon_data += f"\n{output}"
            causal_updates.append(f"Éxito ejecutando bash: {cmd[:20]}...")
        except Exception as e:
            causal_updates.append(f"Falla ejecutando bash: {e}")
            
    elif action_type == "write_proof":
        filename = params.get("filename", "proof.txt")
        file_path = os.path.join(SCRIPT_DIR, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(state["recon_data"])
        print(f"  -> Escrito a disco: {file_path}")
        causal_updates.append(f"Prueba volcada en el path requerido: {filename}")

    return {
        "pending_actions": pending,
        "completed_actions": [current_action],
        "tool_calls_count": state["tool_calls_count"] + 1,
        "current_cost": state["current_cost"] + 0.05,
        "recon_data": new_recon_data,
        "causal_chain": causal_updates
    }

async def reflector_node(state: AgentState) -> dict:
    """[REFLECTOR] Analiza correlación, heurísticas y finalización."""
    
    MAX_COST = 0.50
    if state["current_cost"] > MAX_COST:
        print("\n[Reflector] 🛑 ABORTADO: Límite económico superado!")
        return {"is_aborted": True, "causal_chain": ["Reflector: Costo superado"]}
        
    if not state["pending_actions"]:
        print("\n[Reflector] ✅ GRAFO COMPLETADO EXITOSAMENTE.")
        return {"is_completed": True}

    print("\n[Reflector] 🛡️ Métricas estables. Autorizando continuación.")
    return {"is_aborted": False}

# --- BORDES CONDICIONALES ---
def router_edge(state: AgentState) -> Literal["executor_node", "planner_node", "__end__"]:
    if state.get("is_aborted") or state.get("is_completed"):
        return "__end__"
    if state["pending_actions"]:
        return "executor_node" 
    return "__end__"

# --- COMPILADOR DEL GRAFO ---
def build_langgraph():
    builder = StateGraph(AgentState)
    builder.add_node("quarantine_node", quarantine_node)
    builder.add_node("planner_node", planner_node)
    builder.add_node("executor_node", executor_node)
    builder.add_node("reflector_node", reflector_node)
    builder.add_edge(START, "quarantine_node")
    builder.add_edge("quarantine_node", "planner_node")
    builder.add_edge("planner_node", "executor_node")
    builder.add_edge("executor_node", "reflector_node")
    builder.add_conditional_edges("reflector_node", router_edge)
    return builder.compile()

# --- TEMPORAL.IO WRAPPER & RALPH LOOP ---
async def execute_temporal_workflow():
    db = ExternalStateStore()
    app = build_langgraph()
    prd = load_prd()
    trace_id = str(uuid.uuid4())
    promise_tag = prd.get("promise_tag", "<promise>COMPLETE</promise>")
    
    initial_state = {
        "trace_id": trace_id,
        "mission": prd.get("mission", ""),
        "required_proofs": prd.get("required_proofs", ["proof.txt"]),
        "graph_data": {}, "pending_actions": [],
        "completed_actions": [], "tool_calls_count": 0, "current_cost": 0.0,
        "recon_data": "=== EVIDENCIA RECOPILADA ===\n",
        "causal_chain": [], "is_aborted": False, "is_completed": False
    }
    db.dump_state(initial_state)

    print(f"==================== WORKFLOW START [{trace_id}] ====================")
    
    while True:
        current_state = db.load_state() 
        if current_state.get("is_aborted") or current_state.get("is_completed"):
            break
            
        print("\n>>> NUEVO CICLO (Bucle de Ralph): Recuperando estado desde JSON Storage")

        try:
            final_loop_state = await app.ainvoke(current_state)
            db.dump_state(final_loop_state)
        except Exception as e:
            print(f"Falla fatal: {e}")
            break

    final = db.load_state()
    print(f"\n====================== EJECUCIÓN FINALIZADA ======================")
    print(f"Costo: ${final['current_cost']:.2f} | Acciones realizadas: {final['tool_calls_count']}")
    
    # Imprimir LA PROMESA para pasar el stop-hook.sh si todo funcionó
    if final.get("is_completed"):
        print(f"\n{promise_tag}")

if __name__ == "__main__":
    asyncio.run(execute_temporal_workflow())
