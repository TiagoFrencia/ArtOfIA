import subprocess
import json
import asyncio
from typing import List, Dict, Any

class ReconToolsPro:
    """
    Wrapper de herramientas profesionales. 
    El agente ahora opera software real de hacking.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url

    async def run_nmap(self, target: str):
        """Ejecuta un escaneo de puertos y servicios."""
        print(f"[*] [PRO-RECON] Ejecutando Nmap sobre {target}...")
        # -sV: Versión de servicio, -T4: Velocidad agresiva
        cmd = ["nmap", "-sV", "-T4", target]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode()

    async def run_ffuf(self, wordlist_path: str = "common.txt"):
        """Ejecuta ffuf para descubrimiento de directorios."""
        print(f"[*] [PRO-RECON] Ejecutando ffuf en {self.target_url}...")
        
        # -u: URL, -w: wordlist, -mc: match status code 200
        cmd = [
            "ffuf", 
            "-u", f"{self.target_url}/FUZZ", 
            "-w", wordlist_path, 
            "-mc", "200", 
            "-s", "silent" # Salida limpia para que el LLM no se confunda
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode()

# Singleton para el agente
recon_pro = ReconToolsPro
