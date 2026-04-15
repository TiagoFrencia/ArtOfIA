import time
import httpx
import asyncio
import re
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from typing import Dict, Any, Tuple, Optional
import logging

logger = logging.getLogger("ArtOfIA-Reflector")

class Reflector:
    """
    Nodo Reflector Heurístico (Beast Mode 2.0).
    Capaz de analizar:
    1. Respuestas HTTP (Análisis Estructural, $\Delta t$, Longitud).
    2. Salidas de Herramientas (Análisis de Patrones de Consola/Stdout).
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.network_baseline_ms = 0.0 

    def _simplify_dom(self, html_content: str) -> str:
        """
        Análisis Estructural (Skeletal DOM).
        Elimina ruido dinámico para detectar cambios reales en la arquitectura de la página.
        """
        if not html_content:
            return ""
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for element in soup(["script", "style", "meta", "link", "noscript"]):
                element.decompose()
                
            allowed_attrs = ['name', 'type', 'href', 'action']
            for tag in soup.find_all(True):
                tag.attrs = {k: v for k, v in tag.attrs.items() if k in allowed_attrs}

            return str(soup.body if soup.body else soup)
        except Exception as e:
            logger.error(f"DOM simplification error: {e}")
            return html_content[:1000] # Fallback a texto truncado

    async def _get_network_latency(self) -> float:
        """Mide la latencia base para evitar falsos positivos en Blind SQLi."""
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.get(self.target_url)
        except:
            pass
        return (time.perf_counter() - start) * 1000

    def _analyze_tool_output(self, tool_name: str, output: str) -> Optional[Dict[str, Any]]:
        """
        Analizador de patrones para herramientas profesionales.
        Busca indicadores de éxito en el stdout de la herramienta.
        """
        patterns = {
            "sqlmap": [r"payload:.*", r"database:.*", r"table:.*", r"column:.*", r"fetched.*records"],
            "nmap": [r"open\s+\d+/tcp", r"Service:.*", r"Operating System:.*"],
            "commix": [r"command execution successful", r"executed command:.*"],
            "dirsearch": [r"200\s+OK", r"302\s+Found"],
            "gobuster": [r"Found:.*"],
            "ffuf": [r"\[\d+\]\s+\d+\s+.*"]
        }

        tool_patterns = patterns.get(tool_name, [])
        for pattern in tool_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                return {
                    "type": "tool_success",
                    "tool": tool_name,
                    "evidence": "Pattern match in stdout"
                }
        return None

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orquestador de Reflejo.
        Decide si analizar un HTTP Response (Sniper) o un Tool Output (Arsenal).
        """
        # --- ESCENARIO A: Análisis de salida de Herramienta (ToolExecutor) ---
        if state.get("last_action") == "RUN_TOOL":
            tool_name = state.get("last_tool")
            tool_output = state.get("tool_output", "")
            
            print(f"[*] Reflector: Analizando salida de {tool_name}...")
            tool_result = self._analyze_tool_output(tool_name, tool_output)
            
            if tool_result:
                print(f"[+] ¡ÉXITO! Herramienta {tool_name} confirmó vulnerabilidad.")
                return {
                    "status": "success", 
                    "last_response_metadata": {
                        **tool_result,
                        "vuln_confirmed": state.get("vuln_type", "UNKNOWN")
                    }
                }
            
            print(f"[-] Reflector: {tool_name} no encontró resultados concluyentes.")
            return {"status": "failed", "last_response_metadata": {"type": "tool_no_match"}}

        # --- ESCENARIO B: Análisis de Respuesta HTTP (Sniper) ---
        payload = state.get("current_payload", "")
        vuln_type = state.get("vuln_type", "SQLI")
        
        # Resolución de URL (En integración real, esto viene del SymbolicController)
        url = state.get("resolved_url", f"{self.target_url}?q={payload}") 
        
        if self.network_baseline_ms == 0:
            self.network_baseline_ms = await self._get_network_latency()

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url)
        except Exception as e:
            logger.error(f"Reflector Request Error: {e}")
            return {"status": "failed", "error": str(e)}
        
        duration_ms = (time.perf_counter() - start_time) * 1000
        content = response.text
        simplified_content = self._simplify_dom(content)
        length = len(content)
        
        print(f"[*] Reflector: Recibidos {length} bytes en {duration_ms/1000:.2f}s")

        # 1. DETECCIÓN POR $\Delta t$ (Time-Based)
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

        # 2. DETECCIÓN POR DIFERENCIAL ESTRUCTURAL
        metadata = state.get("last_response_metadata", {})
        prev_skeleton = metadata.get("simplified_content")
        
        if prev_skeleton:
            ratio = SequenceMatcher(None, simplified_content, prev_skeleton).ratio()
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

        # 3. DETECCIÓN POR LONGITUD
        prev_length = metadata.get("length")
        if prev_length and abs(length - prev_length) > 500:
            print(f"[+] ¡ÉXITO! Diferencial de longitud crítico ({prev_length} -> {length}).")
            return {
                "status": "success", 
                "last_response_metadata": {
                    "type": "length_based", 
                    "diff": abs(length - prev_length)
                }
            }

        # 4. ANÁLISIS DE BLOQUEO WAF
        if response.status_code in [403, 406, 429]:
            print(f"[!] Reflector: Bloqueo detectado (HTTP {response.status_code}).")
            return {
                "status": "blocked",
                "last_response_metadata": {
                    "status_code": response.status_code,
                    "length": length,
                    "simplified_content": simplified_content
                }
            }
        
        print(f"[-] Reflector: Intento fallido.")
        return {
            "status": "failed",
            "last_response_metadata": {
                "status_code": response.status_code,
                "length": length,
                "simplified_content": simplified_content
            }
        }
