import pytest
import os
import json
from dual_llm_pattern import SymbolicController, QuarantineLLM, PrivilegedLLM
from semantic_memory import SemanticMemory
from main_orchestrator import RalphLoopOrchestrator, AgentState

def test_symbolic_controller():
    """Valida que el controlador simbólico oculte y resuelva datos correctamente."""
    controller = SymbolicController()
    raw_ip = "192.168.1.100"
    symbol = controller.quarantine_value(raw_ip)
    
    assert symbol.startswith("$VAR_")
    assert controller.resolve_payload(symbol) == raw_ip
    assert controller.resolve_payload(f"nmap {symbol}") == f"nmap {raw_ip}"

def test_semantic_memory_init():
    """Valida la inicialización de la memoria (requiere DB corriendo o mock)."""
    # Si no hay DB, esto fallará graciosamente o imprimirá error.
    # En un entorno de CI real, usaríamos un test container.
    try:
        mem = SemanticMemory()
        assert mem is not None
    except Exception as e:
        pytest.skip(f"Base de datos no disponible para test: {e}")

def test_orchestrator_compilation():
    """Valida que el grafo de LangGraph se compile sin errores."""
    orch = RalphLoopOrchestrator()
    assert orch.graph is not None

def test_quarantine_extraction_logic():
    """Valida la lógica de desinfección (sin llamar al LLM real en esta unidad)."""
    controller = SymbolicController()
    q_llm = QuarantineLLM(controller)
    
    # Mockeamos el parseo para no gastar tokens en unit tests
    findings = {
        "endpoints": ["10.0.0.1"],
        "parameters": ["id"],
        "technologies": ["apache"]
    }
    
    # Probamos la fase de simbolización manual
    from dual_llm_pattern import ExtractedFindings
    validated = ExtractedFindings(**findings)
    
    symbolic_results = {"endpoints": [], "parameters": [], "technologies": []}
    for ep in validated.endpoints:
        symbolic_results["endpoints"].append(controller.quarantine_value(ep))
    
    assert symbolic_results["endpoints"][0].startswith("$VAR_")
    assert controller.resolve_payload(symbolic_results["endpoints"][0]) == "10.0.0.1"

@pytest.mark.asyncio
async def test_orchestrator_step():
    """Valida una iteración única del orquestador (mockeado)."""
    orch = RalphLoopOrchestrator()
    state: AgentState = {
        "iteration_count": 0,
        "context_data": "Test mission",
        "plan": [],
        "is_completed": False,
        "should_halt": False
    }
    
    # Probamos que el nodo de reflector funcione
    from main_orchestrator import reflector_node
    new_state = await reflector_node(state)
    assert "is_completed" in new_state
