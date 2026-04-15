import time
import httpx
from difflib import SequenceMatcher
from typing import Dict, Any
from langgraph.graph import END

class Reflector:
    def __init__(self, target_url: str):
        self.target_url = target_url

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Nodo Reflector Heurístico. 
        Detecta éxitos mediante Tiempo, Longitud y Diferencial de contenido.
        """
        payload = state.get("current_payload", "")
        
        # Preparar la solicitud
        # Nota: Ajusta esto según cómo pases los payloads (Query param, Body, etc.)
        url = f"{self.target_url}?payload={payload}" # Ejemplo simple
        
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
        except Exception as e:
            print(f"[-] Error de red en Reflector: {e}")
            return {"status": "failed", "error": str(e)}
        
        end_time = time.time()
        
        duration = end_time - start_time
        content = response.text
        length = len(content)
        
        print(f"[*] Reflector: Respuesta recibida ({length} bytes) en {duration:.2f}s")

        # --- LÓGICA HEURÍSTICA ---

        # 1. DETECCIÓN TEMPORAL (Time-based Blind)
        # Si el payload incluye un SLEEP y la respuesta tarda > 4s, es éxito.
        if duration > 4.0:
            print(f"[+] ¡ÉXITO HEURÍSTICO! Respuesta lenta detectada ({duration:.2f}s).")
            return {
                "status": "success", 
                "last_response_metadata": {"type": "time_based", "duration": duration}
            }

        # 2. DETECCIÓN POR DIFERENCIAL DE LONGITUD (Length-based Blind)
        # Obtenemos la longitud de la última respuesta guardada en el estado
        metadata = state.get("last_response_metadata", {})
        prev_length = metadata.get("length")
        
        if prev_length and abs(length - prev_length) > 20: 
            print(f"[+] ¡ÉXITO HEURÍSTICO! Cambio de longitud detectado ({prev_length} -> {length}).")
            return {
                "status": "success", 
                "last_response_metadata": {"type": "length_based", "length": length}
            }

        # 3. DETECCIÓN POR SIMILITUD (Content Diffing)
        prev_content = metadata.get("last_content")
        if prev_content:
            ratio = SequenceMatcher(None, content, prev_content).ratio()
            if ratio < 0.8: # Si el contenido cambia más del 20%
                print(f"[+] ¡ÉXITO HEURÍSTICO! Contenido mutado drásticamente (Ratio: {ratio:.2f}).")
                return {
                    "status": "success", 
                    "last_response_metadata": {"type": "diff_based", "ratio": ratio}
                }

        # --- RESULTADO FINAL ---
        # Si no hubo éxito heurístico, determinamos si fue bloqueo o fallo simple
        status = "blocked" if response.status_code in [403, 406, 429] else "failed"
        
        return {
            "status": status,
            "last_response_metadata": {
                "length": length, 
                "last_content": content
            },
            "failed_attempts_summary": state.get("failed_attempts_summary", []) + [{"payload": payload}]
        }
