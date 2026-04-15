import asyncio
import json
import os
from dual_llm_pattern import SymbolicController, QuarantineLLM, PrivilegedLLM
from mutators import mutate_payload

# Simulación de un log de ModSecurity real
MOCK_LOG = """
--84ed0984-A--
[14/Apr/2026:18:00:00 +0000] 127.0.0.1 80 127.0.0.1 443
--84ed0984-C--
user=admin' OR '1'='1
--84ed0984-H--
Message: Access denied with code 403 (phase 2). Pattern match "' OR '1'='1" at ARGS:user. [id "942100"]
"""

async def run_visual_demo():
    print("="*60)
    print("DEMO: FLUJO DE EVASIÓN LOCAL (DRY-RUN)")
    print("="*60)

    # 1. El Corazón Aislante
    print("\n[PASO 1] Inicializando SymbolicController...")
    controller = SymbolicController()

    # 2. Simulación de Cuarentena
    print("[PASO 2] Simulando extracción de datos hostiles (Quarantine)...")
    raw_payload = "admin' OR '1'='1"
    token = controller.quarantine_value(raw_payload)
    print(f"   > El valor '{raw_payload}' ha sido ocultado tras el token: {token}")

    # 3. Simulación de Decisión de Estrategia (Mockeando el LLM para esta demo)
    print("\n[PASO 3] Simulando decisión del Sniper (Local LLM)...")
    # En un caso real, el LLM elegiría esto basándose en el log
    estrategias_disponibles = ['HEX_ENCODE', 'INLINE_COMMENTS', 'CASE_VARIATION', 'URL_DOUBLE_ENCODE', 'NULL_BYTE_INJECTION']
    estrategia_elegida = 'INLINE_COMMENTS' 
    print(f"   > El LLM (qwen2.5-coder) ha determinado la estrategia: {estrategia_elegida}")

    # 4. Mutación Técnica (Python Mutators)
    print("\n[PASO 4] Aplicando mutación técnica vía Python...")
    # Resolvemos el token solo en el momento de la mutación / ejecución
    valor_real = controller.resolve_payload(token)
    payload_mutado = mutate_payload(valor_real, estrategia_elegida)
    print(f"   > Payload Original: {valor_real}")
    print(f"   > Payload Mutado:   {payload_mutado}")

    # 5. Demostración de otras estrategias
    print("\n[PASO 5] Vista previa de otras mutaciones locales:")
    for est in estrategias_disponibles:
        mut = mutate_payload(valor_real, est)
        print(f"   - {est:<20} -> {mut}")

    print("\n" + "="*60)
    print("CONCLUÍDO: El sistema local es capaz de analizar y mutar sin salir a Internet.")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(run_visual_demo())
