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
    Nodo Reflector Heurístico (Beast Mode 4.0 - Hardening).
    Capaz de analizar:
    1. Respuestas HTTP (Análisis Estructural, $\Delta t$, Longitud).
    2. Salidas de Herramientas (Análisis de Patrones de Consola/Stdout).
    3. Análisis de Firmas WAF (Identificación de 'Sabor de Bloqueo' para feedback de L2).
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.network_baseline_ms = 0.0 
        
        # Firmas comunes de WAFs para alimentar la estrategia polimórfica
        self.waf_signatures = {
            "Cloudflare": [r"cloudflare", r"cf-ray", r"ray id"],
            "Akamai": [r"akamai", r"edgecast"],
            "ModSecurity": [r"mod_security", r"modsecurity"],
            "AWS WAF": [r"aws-waf", r"x-amz-waf"],
            "Imperva": [r"incapsula", r"imperva"],
            "Generic_WAF": [r"web application firewall", r"access denied", r"forbidden"]
        }

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

    def _identify_waf_flavor(self, response: httpx.Response) -> str:
        """
        HARDENING FASE 4: Identifica la firma del bloqueo.
        Esto permite que el PrivilegedLLM elija la codificación polimórfica correcta.
        """
        # 1. Analizar Headers
        headers_str = str(response.headers).lower()
        # 2. Analizar Body
        body_str = response.text.lower()
        
        combined_text = headers_str + " " + body_str
        
        for waf, patterns in self.waf_signatures.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return waf
        
        # Fallback basado en código de estado
        if response.status_code == 403: return "WAF_FORBIDDEN"
        if response.status_code == 406: return "WAF_NOT_ACCEPTABLE"
        if response.status_code == 429: return "WAF_RATE_LIMIT"
        
        return "UNKNOWN_BLOCK"

    def _analyze_tool_output(self, tool_name: str, output: str) -> Optional[Dict[str, Any]]:
        """
        Analizador de patrones para herramientas profesionales.
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
        Orquestador de Reflejo (Phase 4).
        Decide si analizar un HTTP Response o un Tool Output.
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

        # --- ESCENARIO B: Análisis de Respuesta HTTP (Sniper / PolyBridge) ---
        payload = state.get("current_payload", "")
        vuln_type = state.get("vuln_type", "SQLI")
        
        # Resolución de URL (Se asume que el orquestador pasa la URL final)
        url = state.get("resolved_url", f"{self.target_url}?q={payload}") 
        
        if self.network_baseline_ms == 0:
            self.network_baseline_ms = await self._get_network_latency()

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
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

        # 4. ANÁLISIS DE BLOQUEO WAF (HARDENING FASE 4)
        if response.status_code in [403, 406, 429] or "access denied" in content.lower():
            waf_flavor = self._identify_waf_flavor(response)
            print(f"[!] Reflector: Bloqueo detectado. Sabor WAF: {waf_flavor} (HTTP {response.status_code}).")
            return {
                "status": "blocked",
                "last_response_metadata": {
                    "status_code": response.status_code,
                    "block_type": waf_flavor, # Información crítica para el PrivilegedLLM
                    "length": length,
                    "simplified_content": simplified_content
                }
            }
        
        print(f"[-] Reflector: Intento fallido (Sin evidencia de éxito ni bloqueo claro).")
        return {
            "status": "failed",
            "last_response_metadata": {
                "status_code": response.status_code,
                "length": length,
                "simplified_content": simplified_content
            }
        }
