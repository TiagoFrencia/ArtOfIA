#!/bin/bash
# ============================================================================
# stop-hook.sh — Interceptor Agresivo de Validación
# ============================================================================
# Captura el flujo de salida del agente y valida empíricamente que:
#   1. La promesa estricta <promise>COMPLETE</promise> fue emitida
#   2. Los archivos de prueba definidos en prd.json realmente existen
#   3. Los archivos no están vacíos
#   4. Los archivos contienen las cadenas requeridas (must_contain)
#   5. Los archivos superan el tamaño mínimo (min_bytes)
#
# Exit codes:
#   0 = TODO validado, el agente puede salir
#   2 = Validación fallida, el Ralph Loop debe reintentar
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE=${1:-""}

if [ -z "$LOG_FILE" ]; then
    echo "[Hook] ERROR FATAL: No se proporcionó archivo de logs."
    exit 2
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "[Hook] ERROR FATAL: El archivo '$LOG_FILE' no existe."
    exit 2
fi

echo ""
echo "┌──────────────────────────────────────────────────┐"
echo "│  STOP-HOOK — Validación de Promesas              │"
echo "└──────────────────────────────────────────────────┘"

# ── PASO 1: Buscar la promesa estricta ──
echo "[Hook] Buscando cadena '<promise>COMPLETE</promise>' en los logs..."

if ! grep -q "<promise>COMPLETE</promise>" "$LOG_FILE"; then
    echo "[Hook] ✗ FALLO: El agente finalizó sin emitir la promesa de completitud."
    echo "[Hook]   El agente dijo que terminó, pero no incluyó el tag obligatorio."
    echo "[Hook]   Esto indica que no ejecutó el paso final o alucinó su finalización."
    exit 2
fi

echo "[Hook] ✓ Promesa <promise>COMPLETE</promise> encontrada en los logs."

# ── PASO 2: Cargar validadores desde prd.json ──
PROOFS_VALID=true

if [ -f "prd.json" ]; then
    echo "[Hook] Cargando validadores desde prd.json..."
    
    # Extraer la lista de archivos requeridos
    REQUIRED_FILES=$(python3 -c "
import json, sys
prd = json.load(open('prd.json'))
for f in prd.get('required_proofs', ['proof.txt']):
    print(f)
" 2>/dev/null)
    
    if [ -z "$REQUIRED_FILES" ]; then
        REQUIRED_FILES="proof.txt"
    fi
    
    for PROOF_FILE in $REQUIRED_FILES; do
        echo ""
        echo "[Hook] Validando archivo de prueba: '$PROOF_FILE'..."
        
        # ── 2a: ¿Existe el archivo? ──
        if [ ! -f "$PROOF_FILE" ]; then
            echo "[Hook] ✗ ALUCINACIÓN: '$PROOF_FILE' NO EXISTE en el filesystem."
            echo "[Hook]   El agente prometió haber completado la tarea pero"
            echo "[Hook]   la evidencia física no fue creada."
            PROOFS_VALID=false
            continue
        fi
        echo "[Hook]   ✓ Archivo existe."
        
        # ── 2b: ¿Está vacío? ──
        if [ ! -s "$PROOF_FILE" ]; then
            echo "[Hook] ✗ ALUCINACIÓN: '$PROOF_FILE' existe pero está VACÍO (0 bytes)."
            PROOFS_VALID=false
            continue
        fi
        
        ACTUAL_SIZE=$(wc -c < "$PROOF_FILE" | tr -d ' ')
        echo "[Hook]   ✓ Archivo contiene $ACTUAL_SIZE bytes."
        
        # ── 2c: Validar min_bytes desde prd.json ──
        MIN_BYTES=$(python3 -c "
import json
prd = json.load(open('prd.json'))
v = prd.get('proof_validators', {}).get('$PROOF_FILE', {})
print(v.get('min_bytes', 1))
" 2>/dev/null || echo "1")
        
        if [ "$ACTUAL_SIZE" -lt "$MIN_BYTES" ]; then
            echo "[Hook] ✗ FALLO: '$PROOF_FILE' tiene $ACTUAL_SIZE bytes, mínimo requerido: $MIN_BYTES."
            PROOFS_VALID=false
            continue
        fi
        echo "[Hook]   ✓ Tamaño mínimo ($MIN_BYTES bytes) superado."
        
        # ── 2d: Validar must_contain desde prd.json ──
        MUST_CONTAIN=$(python3 -c "
import json
prd = json.load(open('prd.json'))
v = prd.get('proof_validators', {}).get('$PROOF_FILE', {})
for kw in v.get('must_contain', []):
    print(kw)
" 2>/dev/null)
        
        if [ -n "$MUST_CONTAIN" ]; then
            for KEYWORD in $MUST_CONTAIN; do
                if grep -qi "$KEYWORD" "$PROOF_FILE"; then
                    echo "[Hook]   ✓ Cadena requerida '$KEYWORD' encontrada."
                else
                    echo "[Hook] ✗ FALLO: Cadena requerida '$KEYWORD' NO encontrada en '$PROOF_FILE'."
                    PROOFS_VALID=false
                fi
            done
        fi
    done
else
    # Fallback si no hay prd.json: validar solo proof.txt
    echo "[Hook] WARN: prd.json no encontrado. Usando validación por defecto (proof.txt)."
    if [ ! -f "proof.txt" ] || [ ! -s "proof.txt" ]; then
        echo "[Hook] ✗ FALLO: proof.txt no existe o está vacío."
        PROOFS_VALID=false
    else
        echo "[Hook] ✓ proof.txt existe y tiene contenido."
    fi
fi

# ── VEREDICTO FINAL ──
echo ""
if [ "$PROOFS_VALID" = true ]; then
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  ✓ STOP-HOOK: TODAS LAS VALIDACIONES SUPERADAS ║"
    echo "╚══════════════════════════════════════════════════╝"
    exit 0
else
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  ✗ STOP-HOOK: ALUCINACIÓN / TAREA INCOMPLETA   ║"
    echo "║  Bloqueando salida — Exit Code 2                ║"
    echo "╚══════════════════════════════════════════════════╝"
    exit 2
fi
