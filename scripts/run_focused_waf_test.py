import asyncio
import os
import json
from main_orchestrator import RalphLoopOrchestrator

async def run_focused_test():
    print("\n" + "="*60)
    print(" [TARGETED TEST] EXCLUSIVAMENTE MODO SNIPER (WAF EVASION)")
    print("="*60 + "\n")
    
    # Limpiar estado previo
    if os.path.exists("progress.txt"):
        os.remove("progress.txt")
    if os.path.exists("IMPLEMENTATION_PLAN.md"):
        os.remove("IMPLEMENTATION_PLAN.md")
    
    # Simular un ataque inicial bloqueado para disparar el Sniper Mode
    initial_directive = """
    Objetivo: http://target-waf/
    Estado Actual: Acabamos de recibir un HTTP 406 NOT ACCEPTABLE al intentar inyectar '1' OR '1'='1' en el parámetro 'user'.
    Misión: Analizar logs del WAF en /app/logs/modsec_audit.log y realizar un bypass manual quirúrgico.
    """
    
    orchestrator = RalphLoopOrchestrator()
    
    try:
        # Ejecutar el Ralph Loop (P-E-R)
        await orchestrator.execute_task(initial_directive)
        
        # Cargar resultado final
        final_state = orchestrator.state_manager.load_state()
        
        report = {
            "target": "WAF-Evasion-Targeted",
            "evasion_success": final_state.get("evasion_success", False),
            "compromise_success": final_state.get("is_completed", False),
            "iterations": final_state.get("iteration_count", 0),
            "mode": final_state.get("execution_mode", "sniper")
        }
        
        print("\n" + "="*60)
        print(" RESULTADO FINAL DE LA MISIÓN SNIPER")
        print("="*60)
        print(json.dumps(report, indent=4))
        
        # Guardar como benchmark_report.json (sobrescribir)
        with open("benchmark_report.json", "w") as f:
            json.dump([report], f, indent=4)
            
    except Exception as e:
        print(f"[ERROR] La simulación falló: {e}")

if __name__ == "__main__":
    asyncio.run(run_focused_test())
