#!/bin/bash
# ============================================================================
# ralph_loop.sh — Orquestador del Patrón Ralph Loop
# ============================================================================
# Invoca al agente ReAct repetidamente con contexto limpio (sin historial 
# de chat). El agente debe leer su misión desde prd.json y su estado desde
# progress.txt. Después de cada ejecución, stop-hook.sh valida que el agente
# realmente cumplió y no alucinó.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Leer max retries desde prd.json si existe, sino usar 10
MAX_RETRIES=10
if [ -f "prd.json" ]; then
    PARSED=$(python3 -c "import json; print(json.load(open('prd.json')).get('max_ralph_retries', 10))" 2>/dev/null || echo "10")
    MAX_RETRIES=$PARSED
fi

echo "========================================================"
echo "         PATRÓN RALPH LOOP — INICIANDO"
echo "========================================================"
echo "[Config] Max reintentos: $MAX_RETRIES"
echo "[Config] Directorio de trabajo: $SCRIPT_DIR"
echo ""

# Limpiar artefactos de ejecuciones previas 
# (progress.txt se mantiene intencionalmente para dar contexto entre reintentos)
rm -f agent_output.log
rm -f proof.txt

RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    ((RETRY_COUNT++))
    
    echo ""
    echo "┌──────────────────────────────────────────────────┐"
    echo "│  RALPH LOOP — Iteración #$RETRY_COUNT / $MAX_RETRIES"
    echo "└──────────────────────────────────────────────────┘"
    
    # ── 1. Invocar al agente con contexto limpio ──
    # El agente NO recibe historial de chat. Su única fuente de verdad son:
    #   - prd.json     (misión inmutable)
    #   - progress.txt (estado acumulado entre reintentos)
    python3 react_agent.py > agent_output.log 2>&1
    AGENT_EXIT=$?
    
    # Mostrar la salida capturada
    echo ""
    echo "--- SALIDA DEL AGENTE (agent_output.log) ---"
    cat agent_output.log
    echo "--- FIN SALIDA ---"
    echo ""
    
    if [ $AGENT_EXIT -ne 0 ]; then
        echo "[Ralph Loop] WARN: El agente terminó con exit code $AGENT_EXIT"
    fi
    
    # ── 2. Interceptar con stop-hook.sh ──
    echo "[Ralph Loop] Ejecutando validación: stop-hook.sh..."
    bash stop-hook.sh agent_output.log
    HOOK_EXIT=$?
    
    if [ $HOOK_EXIT -eq 0 ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════╗"
        echo "║  ✓ RALPH LOOP COMPLETADO EXITOSAMENTE           ║"
        echo "║  Intentos requeridos: $RETRY_COUNT               "
        echo "╚══════════════════════════════════════════════════╝"
        echo ""
        echo "[+] Evidencia final en proof.txt:"
        cat proof.txt
        exit 0
    fi
    
    # ── 3. Fallo: preparar para reintento ──
    echo ""
    echo "[Ralph Loop] ✗ Validación fallida (exit code: $HOOK_EXIT)"
    echo "[Ralph Loop] El agente será reiniciado con contexto limpio."
    echo "[Ralph Loop] El archivo progress.txt se mantiene para dar contexto al próximo intento."
    
    # Agregar nota de fallo al progress.txt para que el siguiente intento sepa qué pasó
    echo "" >> progress.txt
    echo "--- RALPH LOOP: INTENTO #$RETRY_COUNT FALLIDO ($(date '+%Y-%m-%d %H:%M:%S')) ---" >> progress.txt
    echo "Razón: El stop-hook.sh retornó exit code $HOOK_EXIT." >> progress.txt
    echo "El agente debe revisar su enfoque y completar la misión definida en prd.json." >> progress.txt
    
    # Limpiar proof.txt parcial/corrupto si existe
    rm -f proof.txt
    
    sleep 2
done

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✗ RALPH LOOP AGOTADO — MAX REINTENTOS ALCANZADO   ║"
echo "║  El agente no logró completar la tarea en           ║"
echo "║  $MAX_RETRIES intentos. Intervención manual           "
echo "║  requerida.                                          ║"
echo "╚══════════════════════════════════════════════════════╝"
exit 1
