import time
import httpx
import asyncio
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from typing import Dict, Any, Tuple, Optional
from langgraph.graph import END

class Reflector:
    """
    Nodo Reflector Heurístico (Beast Mode).
    Detecta éxitos mediante Análisis Estructural (DOM), Diferenciales de Tiempo ($\Delta t$)
    y Análisis de Longitud.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        # Baseline para evitar falsos positivos por latencia de red
        self.network_baseline_ms = 0.0 

    def _simplify_dom(self, html_content: str) -> str:
        """
        Sustituye el análisis de texto plano por un Análisis Estructural.
        Elimina ruido: scripts, estilos, comentarios y atributos dinámicos.
        """
        if not html_content:
            return ""
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Eliminar elementos que generan ruido dinámico
        for element in soup(["script", "style", "meta", "link", "noscript"]):
            element.decompose()
            
        # 2. Limpiar atributos dinámicos (IDs generados, nonces, timestamps)
        # Solo mantenemos atributos críticos como 'name', 'type', 'href'
        allowed_attrs = ['name', 'type', 'href', 'action']
        for tag in soup.find_all(True):
            tag.attrs = {k: v for k, v in tag.attrs.items() if k in allowed_attrs}

        # Retornamos la estructura del DOM simplificada (estilo esqueleto)
        return str(soup.body if soup.body else soup) if soup else ""

    async def _get_network_latency(self) -> float:
        """Mide la latencia base del servidor para ajustar el umbral de $\Delta t$."""
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.get(self.target_url)
        except:
            pass
        return (time.perf_counter() - start) * 1000

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta la petición y juzga la respuesta basándose en heurísticas avanzadas.
        """
        payload = state.get("current_payload", "")
        vuln_type = state.get("vuln_type", "SQLI")
        
        # Construcción de la URL (en un escenario real, esto vendría del SymbolicController)
        # Aquí simulamos que el payload se inyecta en un parámetro 'q'
        url = f"{self.target_url}?q={payload}" 
        
        # Calibración de red si no existe baseline
        if self.network_baseline_ms == 0:
            self.network_baseline_ms = await self._get_network_latency()

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url)
        except Exception as e:
            print(f"[-] Reflector Error: {e}")
            return {"status": "failed", "error": str(e)}
        
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        
        content = response.text
        simplified_content = self._simplify_dom(content)
        length = len(content)
        
        print(f"[*] Reflector: Recibidos {length} bytes en {duration_ms/1000:.2f}s")

        # --- LÓGICA DE JUICIO BEAST MODE ---

        # 1. DETECCIÓN POR DELTA DE TIEMPO ($\Delta t$)
        # Si la respuesta tarda significativamente más que el baseline + el sleep del payload
        # Ejemplo: Baseline 100ms + Payload Sleep 5s = > 5.1s es éxito.
        if duration_ms > (5000 + self.network_baseline_ms):
            print(f"[+] ¡ÉXITO! Anomalía temporal detectada ($\Delta t$ = {duration_ms:.2f}ms).")
            return {
                "status": "success", 
                "last_response_metadata": {
                    "type": "time_based", 
                    "delta_t": duration_ms, 
                    "vuln_confirmed": vuln_type
                }
            }

        # 2. DETECCIÓN POR DIFERENCIAL ESTRUCTURAL (SKELETON DIFF)
        metadata = state.get("last_response_metadata", {})
        prev_skeleton = metadata.get("simplified_content")
        
        if prev_skeleton:
            # Comparamos el esqueleto actual contra el anterior
            ratio = SequenceMatcher(None, simplified_content, prev_skeleton).ratio()
            
            # Si el ratio es bajo (< 0.85), la estructura de la página cambió (ej. apareció un error de SQL o un archivo LFI)
            if ratio < 0.85:
                print(f"[+] ¡ÉXITO! Cambio estructural detectado (Ratio: {ratio:.2f}).")
                return {
                    "status": "success", 
                    "last_response_metadata": {
                        "type": "structural_diff", 
                        "ratio": ratio, 
                        "vuln_confirmed": vuln_type
                    }
                }

        # 3. DETECCIÓN POR LONGITUD (Criterio Secundario)
        prev_length = metadata.get("length")
        if prev_length and abs(length - prev_length) > 500: # Cambio masivo de contenido
            print(f"[+] ¡ÉXITO! Diferencial de longitud crítico ({prev_length} -> {length}).")
            return {
                "status": "success", 
                "last_response_metadata": {
                    "type": "length_based", 
                    "diff": abs(length - prev_length)
                }
            }

        # --- ANÁLISIS DE BLOQUEO ---
        # Si no hubo éxito, determinamos si el WAF nos detuvo
        # 403 Forbidden, 406 Not Acceptable, 429 Too Many Requests
        status_code = response.status_code
        if status_code in [403, 406, 429]:
            print(f"[!] Reflector: Bloqueo detectado (HTTP {status_code}).")
            return {
                "status": "blocked",
                "last_response_metadata": {
                    "status_code": status_code,
                    "length": length,
                    "simplified_content": simplified_content
                }
            }
        
        # Si llegamos aquí, el ataque falló pero no fue bloqueado
        print(f"[-] Reflector: Intento fallido (Sin anomalías detectadas).")
        return {
            "status": "failed",
            "last_response_metadata": {
                "status_code": status_code,
                "length": length,
                "simplified_content": simplified_content
            },
            "failed_attempts_summary": state.get("failed_attempts_summary", []) + [{"payload": payload}]
        }
