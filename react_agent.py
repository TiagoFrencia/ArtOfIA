import re
import subprocess
import json
import os
import sys
import asyncio

# ============================================================================
# REACT AGENT — RALPH LOOP AWARE
# ============================================================================
# Este agente arranca SIN memoria de conversaciones previas.
# Su único contexto viene de archivos físicos en disco:
#   - prd.json    → misión, validadores, configuración
#   - progress.txt → estado acumulado entre reintentos del Ralph Loop
#
# El Ralph Loop (ralph_loop.sh) lo invoca repetidamente con contexto limpio.
# El stop-hook.sh valida que el agente no alucinó antes de dejarlo salir.
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_prd() -> dict:
    """
    Carga la definición de misión desde prd.json.
    Si no existe, retorna una misión por defecto.
    """
    prd_path = os.path.join(SCRIPT_DIR, "prd.json")
    if os.path.exists(prd_path):
        with open(prd_path, "r", encoding="utf-8") as f:
            prd = json.load(f)
        print(f"[Agente] Misión cargada desde prd.json: {prd.get('mission', 'N/A')[:80]}...")
        return prd
    else:
        print("[Agente] WARN: prd.json no encontrado. Usando misión por defecto.")
        return {
            "mission": "Reconocimiento básico de la máquina local. Guardar resultados en proof.txt.",
            "required_proofs": ["proof.txt"],
            "promise_tag": "<promise>COMPLETE</promise>",
            "agent_max_iterations": 5,
            "agent_timeout_seconds": 15,
        }


def load_progress() -> str:
    """
    Lee el estado acumulado del archivo progress.txt.
    Este archivo persiste entre reintentos del Ralph Loop,
    permitiendo al agente saber qué ya intentó en iteraciones anteriores.
    """
    progress_path = os.path.join(SCRIPT_DIR, "progress.txt")
    if os.path.exists(progress_path):
        with open(progress_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        print(f"[Agente] Estado previo cargado desde progress.txt ({len(content)} bytes)")
        return content
    return ""


def save_progress(content: str):
    """
    Persiste el estado actual al disco para que sobreviva entre
    invocaciones limpias del Ralph Loop.
    """
    progress_path = os.path.join(SCRIPT_DIR, "progress.txt")
    with open(progress_path, "w", encoding="utf-8") as f:
        f.write(content)


def determine_action(llm_response: str) -> str:
    """
    Procesa la respuesta del LLM y extrae estrictamente el código a ejecutar.
    Usa extracción robusta con regex multilínea para capturar bloques Markdown.
    """
    pattern = re.compile(r"^```(?:\w+)?\s*\n(.*?)(?=^```)", re.DOTALL | re.MULTILINE)
    match = pattern.search(llm_response)

    if match:
        return match.group(1).strip()
    return ""


def execute_action(command: str, history: str, iteration: int, prd: dict) -> str:
    """
    Canaliza el comando extraído hacia la terminal del sistema.
    Incluye timeout configurable desde prd.json para evitar bloqueos
    por comandos como escuchas de red (nc -lvnp), nmap pesados, etc.

    Comandos especiales del agente:
      WAF_SCAN:<url>|<param>       → invoca el scanner WAF adaptativo
      WAF_SCAN:<url>|<param>|<delay>  → idem con delay personalizado
    """
    timeout = prd.get("agent_timeout_seconds", 15)
    print(f"\n[Acción - Iteración {iteration}] Ejecutando comando:\n  $ {command}\n")

    # ── Detección de comando WAF especializado ──
    if command.strip().startswith("WAF_SCAN:"):
        observacion = _execute_waf_scan(command, iteration)
    else:
        observacion = _execute_shell_command(command, timeout)

    print(f"[Observación]:\n{observacion}")

    # Anexar al historial y persistir en disco
    history += f"\n\n--- Iteración {iteration} ---\nComando ejecutado:\n  $ {command}\n\n{observacion}"
    save_progress(history)

    # Llamada recursiva al siguiente ciclo de pensamiento
    return think(history, iteration + 1, prd)


def _execute_shell_command(command: str, timeout: int) -> str:
    """
    Ejecuta un comando shell estándar via subprocess.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = result.stdout + result.stderr
        if not output.strip():
            output = "[Comando ejecutado exitosamente sin salida visible]"

        return f"Observación:\n{output}"

    except subprocess.TimeoutExpired:
        return f"Observación:\n[TIMEOUT] El comando superó {timeout}s y fue terminado."
    except Exception as e:
        return f"Observación:\n[ERROR] {str(e)}"


def _execute_waf_scan(command: str, iteration: int) -> str:
    """
    Rutea al módulo waf_evasion.py para ejecutar el scanner adaptativo.
    Formato esperado:
      WAF_SCAN:<url>|<param>
      WAF_SCAN:<url>|<param>|<delay_seconds>
    """
    try:
        from waf_evasion import run_waf_evasion_scan, format_scan_report, save_report_to_disk

        # Parsear argumentos del comando especial
        raw_args = command.strip().replace("WAF_SCAN:", "", 1)
        parts = [p.strip() for p in raw_args.split("|")]

        target_url = parts[0] if len(parts) > 0 else "http://localhost"
        param = parts[1] if len(parts) > 1 else "id"
        delay = float(parts[2]) if len(parts) > 2 else 5.0

        print(f"[WAF Module] Invocando scanner adaptativo...")
        print(f"  Target: {target_url}")
        print(f"  Param:  {param}")
        print(f"  Delay:  {delay}s")

        # Ejecutar el escaneo asíncrono
        report = asyncio.run(run_waf_evasion_scan(
            target_url=target_url,
            param=param,
            injected_delay=delay,
        ))

        # Persistir reporte en disco
        save_report_to_disk(report)

        # Formatear como observación para el agente
        return f"Observación:\n{format_scan_report(report)}"

    except ImportError:
        return (
            "Observación:\n[ERROR] El módulo waf_evasion.py no está disponible. "
            "Asegúrate de que existe en el mismo directorio que react_agent.py."
        )
    except Exception as e:
        return f"Observación:\n[ERROR WAF SCAN] {str(e)}"


def call_llm_api(prompt: str) -> str:
    """
    Abstracción de la llamada al LLM.
    
    TODO: Conectar a tu implementación real:
      - POST http://brain:8000/route  (dentro de Docker)
      - API directa de Ollama (http://host.docker.internal:11434/api/generate)
      - API de Gemini (generativelanguage.googleapis.com)
    
    El mock actual simula un agente que:
      1. Ejecuta hostname + whoami
      2. Ejecuta ipconfig y netstat 
      3. Escribe proof.txt con los resultados y emite la promesa
    """
    print("[LLM] Simulando llamada al modelo...")

    # Contamos las observaciones previas para saber en qué paso estamos
    obs_count = prompt.count("Observación:")

    if obs_count == 0:
        return (
            "Primero necesito identificar la máquina. Voy a obtener el hostname "
            "y el usuario actual.\n"
            "```bash\n"
            "echo '=== hostname ===' && hostname && echo '=== whoami ===' && whoami\n"
            "```"
        )
    elif obs_count == 1:
        return (
            "Ahora necesito las interfaces de red y puertos abiertos.\n"
            "```bash\n"
            "echo '=== interfaces ===' && ipconfig && echo '=== puertos ===' && netstat -an | head -30\n"
            "```"
        )
    else:
        # Paso final: escribir proof.txt y emitir promesa
        return (
            "Ya tengo toda la información. Voy a compilar la evidencia en proof.txt "
            "y emitir la señal de finalización.\n"
            "```bash\n"
            'echo "=== PROOF OF RECON ===" > proof.txt\n'
            'echo "hostname: $(hostname)" >> proof.txt\n'
            'echo "user: $(whoami)" >> proof.txt\n'
            'echo "interfaces: $(ipconfig 2>/dev/null || ip addr 2>/dev/null)" >> proof.txt\n'
            'echo "=== END ===" >> proof.txt\n'
            'echo "<promise>COMPLETE</promise>"\n'
            "```"
        )


def build_system_prompt(prd: dict) -> str:
    """
    Construye el prompt de sistema inyectando la misión y las reglas
    directamente desde prd.json. El agente NUNCA improvisa su objetivo.
    """
    mission = prd.get("mission", "No hay misión definida.")
    proofs = ", ".join(prd.get("required_proofs", []))
    promise_tag = prd.get("promise_tag", "<promise>COMPLETE</promise>")

    return f"""Eres un agente autónomo de ciberseguridad operando bajo el framework ReAct (Razonamiento + Acción).

=== TU MISIÓN (INMUTABLE — LEÍDA DESDE prd.json) ===
{mission}

=== REGLAS ESTRICTAS ===
1. En cada turno, razona brevemente y luego emite UN SOLO bloque de código bash.
2. Cuando completes TODOS los objetivos, tu último comando DEBE:
   a) Escribir la evidencia en los archivos requeridos: [{proofs}]
   b) Imprimir exactamente la cadena {promise_tag} en stdout.
3. Si no emites la promesa, serás reiniciado automáticamente (Ralph Loop).
4. Si emites la promesa pero los archivos de prueba no existen o están vacíos, 
   serás marcado como ALUCINACIÓN y reiniciado.
5. No inventes resultados. Ejecuta comandos reales y reporta lo que observas.

=== HERRAMIENTA ESPECIAL: WAF EVASION SCANNER ===
Puedes invocar el módulo de evasión WAF con heurísticas adaptativas.
En lugar de escribir un comando bash, emite el siguiente formato:

  WAF_SCAN:<url_objetivo>|<parámetro_vulnerable>
  WAF_SCAN:<url_objetivo>|<parámetro_vulnerable>|<delay_segundos>

Ejemplo:
  WAF_SCAN:http://target.com/page.php|id
  WAF_SCAN:http://target.com/page.php|id|5

Este módulo automáticamente:
  - Lanza inyecciones básicas para detectar presencia de WAF
  - Si detecta WAF (403s recurrentes, cabeceras de firma), detiene ese vector
  - Muta a Time-Based Blind SQLi adaptado al motor de BD (MySQL/PostgreSQL/MSSQL)
  - Valida empíricamente la vulnerabilidad midiendo latencia asíncrona
  - Guarda el reporte completo en waf_scan_report.json

Formato de respuesta:
Tu razonamiento aquí...
```bash
tu_comando_aqui
```"""


def think(history: str = "", iteration: int = 1, prd: dict = None) -> str:
    """
    Orquestador principal del ciclo ReAct.
    - Gestiona el contador de iteraciones (anti-loop infinito)
    - Estructura el prompt del sistema desde prd.json
    - Llama al LLM
    - Delega a determine_action → execute_action recursivamente
    """
    if prd is None:
        prd = load_prd()

    max_iter = prd.get("agent_max_iterations", 5)

    if iteration > max_iter:
        print(f"\n[!] Límite de iteraciones ({max_iter}) alcanzado. Finalizando ejecución.")
        save_progress(history)
        return history

    print(f"\n{'='*50}")
    print(f"  THINK — Iteración {iteration}/{max_iter}")
    print(f"{'='*50}")

    system_prompt = build_system_prompt(prd)
    full_prompt = f"{system_prompt}\n\n[Estado y observaciones previas]:\n{history}\n\n¿Cuál es tu siguiente acción?"

    llm_response = call_llm_api(full_prompt)
    print(f"\n[Pensamiento LLM]:\n{llm_response}")

    action_command = determine_action(llm_response)

    if action_command:
        return execute_action(action_command, history, iteration, prd)
    else:
        print("\n[!] El LLM no retornó un bloque de código ejecutable.")
        save_progress(history)
        return history


# ============================================================================
# ENTRY POINT — Invocado por ralph_loop.sh con contexto limpio
# ============================================================================
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AGENTE ReAct — RALPH LOOP AWARE")
    print("=" * 60)

    # 1. Cargar misión desde disco (NO desde memoria/historial)
    prd = load_prd()

    # 2. Cargar estado previo (si hay reintentos del Ralph Loop)
    progress = load_progress()

    # 3. Si hay progreso previo, incluirlo como contexto inicial
    if progress:
        initial_context = (
            f"[CONTEXTO PREVIO — leído desde progress.txt]\n"
            f"{progress}\n\n"
            f"[NOTA] Eres una nueva instancia del agente. El intento anterior "
            f"NO completó la tarea. Revisa qué falló arriba y corrige tu enfoque."
        )
    else:
        initial_context = f"Inicio limpio. Misión: {prd.get('mission', 'N/A')}"

    # 4. Arrancar el ciclo ReAct
    think(initial_context, iteration=1, prd=prd)

    print("\n\n======== EJECUCIÓN DEL AGENTE TERMINADA ========")
