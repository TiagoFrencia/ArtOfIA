from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from pydantic import BaseModel, Field

# ---------------------------------------------------------
# DOMAIN MODELS
# ---------------------------------------------------------
class FailureLevel(str, Enum):
    L1_TOOL_ERROR = "L1_TOOL_ERROR"
    L2_INVALID_HYPOTHESIS = "L2_INVALID_HYPOTHESIS"
    L3_ENVIRONMENT_BLOCK = "L3_ENVIRONMENT_BLOCK"
    L4_DEAD_END = "L4_DEAD_END"

class ExecutionResult(BaseModel):
    action_id: str
    action_name: str
    success: bool
    output: str
    error_msg: Optional[str] = None

class TaskState(BaseModel):
    """Representación inmutable del estado actual para el análisis del reflector."""
    tool_calls: int = 0
    current_cost: float = 0.0
    evidence_fingerprints: List[str] = Field(default_factory=list) # Track evidence evolution
    recent_results: List[ExecutionResult] = Field(default_factory=list)
    max_tool_calls: int = 40
    max_cost: float = 0.30
    rabbit_hole_threshold: int = 4  # N steps sin nueva evidencia

# ---------------------------------------------------------
# REFLECTOR COMPONENT
# ---------------------------------------------------------
class Reflector:
    """
    Componente Reflector (R) para la arquitectura P-E-R.
    Responsable de Failure Attribution, Detección de Bucles e Intervención Temprana.
    Objetivo Económico: Costo medio de éxito < $0.09.
    """
    
    def analyze_failure_attribution(self, result: ExecutionResult) -> Optional[FailureLevel]:
        """Clasificación de errores basada en patrones L1-L4."""
        if result.success:
            return None
            
        err = (result.error_msg or "").lower()
        output = (result.output or "").lower()
        
        # L3: Environment Block (WAF, IPS, Firewall Drops)
        if any(kw in err or kw in output for kw in ["403 forbidden", "waf", "connection reset", "blocked", "captcha"]):
            return FailureLevel.L3_ENVIRONMENT_BLOCK
            
        # L1: Tool Error (Syntax, Timeouts, Missing Binaries)
        if any(kw in err or kw in output for kw in ["syntax error", "not found", "timeout limit", "validation error", "unrecognized argument"]):
            return FailureLevel.L1_TOOL_ERROR
            
        # L2: Invalid Hypothesis (Service not matching expected exploit context)
        if any(kw in err or kw in output for kw in ["not vulnerable", "version mismatch", "0 hosts up", "access denied"]):
            return FailureLevel.L2_INVALID_HYPOTHESIS
            
        # L4: Default Fallback para fallos abstractos estructurales
        return FailureLevel.L4_DEAD_END

    def detect_rabbit_hole(self, state: TaskState) -> Tuple[bool, str]:
        """
        Detecta si el agente entró en una madriguera (Loop infinito cognitivo).
        Regla: Sin nueva evidencia durante los últimos N pasos.
        """
        if len(state.evidence_fingerprints) < state.rabbit_hole_threshold:
            return False, ""
            
        # Revisamos los últimos N pasos
        recent_evidence = state.evidence_fingerprints[-state.rabbit_hole_threshold:]
        
        # Si la huella de evidencia no cambió en N pasos, estamos atrapados
        if len(set(recent_evidence)) == 1:
            return True, f"Agente atrapado: La evidencia no ha mutado en los últimos {state.rabbit_hole_threshold} pasos consecutivos."
            
        return False, ""

    def should_halt(self, state: TaskState) -> Tuple[bool, str]:
        """
        Calcula las reglas de Early Stopping limitadas por hardware.
        """
        # Hardcoded Economic & Tool Rules
        if state.tool_calls >= state.max_tool_calls:
            return self.halt_task(f"Límite máximo de tool calls alcanzado ({state.tool_calls}/{state.max_tool_calls}).")
            
        if state.current_cost >= state.max_cost:
            return self.halt_task(f"Límite de presupuesto excedido (${state.current_cost:.2f}/${state.max_cost:.2f}).")
            
        # Detección Algorítmica de Rabbit Holes
        is_stuck, reason = self.detect_rabbit_hole(state)
        if is_stuck:
            return self.halt_task(reason)
            
        return False, "Operación dentro de umbrales aceptables."

    def halt_task(self, reason: str) -> Tuple[bool, str]:
        """Señal formal para finalizar el Workflow de Temporal."""
        print(f"\n[REFLECTOR HALT SIGNAL ACTIVADA]\nMotivo: {reason}\nIniciando terminación limpia de la tarea...")
        return True, reason

# ---------------------------------------------------------
# DEMONSTRATION
# ---------------------------------------------------------
if __name__ == "__main__":
    reflector = Reflector()
    
    # Simulación de Estado Abortivo Económico
    print("--- Test 1: Prevención Económica ---")
    state_expensive = TaskState(tool_calls=15, current_cost=0.35)
    halt, reason = reflector.should_halt(state_expensive)
    print(f"Halt: {halt} | Reason: {reason}\n")
    
    # Simulación de Rabbit Hole
    print("--- Test 2: Rabbit Hole Analysis ---")
    stuck_state = TaskState(
        tool_calls=12,
        current_cost=0.08,
        # Misma huella criptográfica ("hash_evidence") 4 veces seguidas
        evidence_fingerprints=["hash_A", "hash_B", "hash_C", "hash_C", "hash_C", "hash_C"] 
    )
    halt, reason = reflector.should_halt(stuck_state)
    print(f"Halt: {halt} | Reason: {reason}\n")
    
    # Simulación de Failure Attribution
    print("--- Test 3: L1-L4 Failure Attribution ---")
    res_l3 = ExecutionResult(
        action_id="sql_inject", action_name="send_payload", success=False, 
        output="Cloudflare captcha detected, 403 Forbidden.", error_msg=""
    )
    failure_type = reflector.analyze_failure_attribution(res_l3)
    print(f"Resultado clasificado como: {failure_type.value}")
