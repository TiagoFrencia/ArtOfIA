import asyncio
import os
import time
from main_orchestrator import RalphLoopOrchestrator

async def force_sniper_test():
    print("\n" + "="*60)
    print(" [SIMULACIÓN FORZADA] TEST DE MODO FRANCOTIRADOR")
    print("="*60 + "\n")

    # 0. Limpiar estado anterior para un test fresco
    if os.path.exists("progress.txt"):
        os.remove("progress.txt")
    
    # 1. Escenario: El agente ya intentó algo automático y falló con 406
    # Forzamos este estado en el contexto inicial para gatillar el router
    initial_directive = """
    Objetivo: http://target-waf/
    Estado Actual: Acabamos de recibir un HTTP 406 NOT ACCEPTABLE al intentar inyectar '1' OR '1'='1' en el parámetro 'user'.
    Misión: Analizar logs del WAF y realizar un bypass manual (SNIPER MODE).
    """
    
    orchestrator = RalphLoopOrchestrator()
    
    # Aseguramos que el log de auditoría esté accesible para la prueba
    if not os.path.exists("/app/logs/modsec_audit.log"):
        print("[AVISO] El archivo de logs /app/logs/modsec_audit.log no existe aún.")
        print("Intentando generar tráfico para disparar el log...")
        # (Esto se ejecutará dentro del contenedor 'brain' vía docker exec)
    
    print(">>> Iniciando Ralph Loop con el contexto de bloqueo forzado...")
    try:
        await orchestrator.execute_task(initial_directive)
        
        final_state = orchestrator.state_manager.load_state()
        print("\n" + "="*60)
        print(" RESULTADO FINAL DEL TEST")
        print("="*60)
        print(f"Modo de Ejecución: {final_state.get('execution_mode')}")
        print(f"Evasión Lograda: {'SÍ' if final_state.get('evasion_success') else 'NO'}")
        print(f"Iteraciones: {final_state.get('iteration_count')}")
        
    except Exception as e:
        print(f"\n[ERROR CRÍTICO] El test falló: {e}")

if __name__ == "__main__":
    asyncio.run(force_sniper_test())
