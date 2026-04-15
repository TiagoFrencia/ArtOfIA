import asyncio
from typing import List, Dict, Any

class ReconToolsPro:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.worker_container = "ai-worker"

    async def _run_docker_cmd(self, cmd_list: List[str]) -> str:
        """Ejecuta cualquier comando dentro del contenedor ai-worker."""
        full_cmd = ["docker", "exec", self.worker_container] + cmd_list
        process = await asyncio.create_subprocess_exec(
            *full_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode() if process.returncode == 0 else stderr.decode()

    # --- HERRAMIENTAS DE RECON ---
    async def run_nmap(self, target: str):
        return await self._run_docker_cmd(["nmap", "-sV", "-T4", "-Pn", target])

    async def run_ffuf(self, wordlist: str = "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt"):
        return await self._run_docker_cmd(["ffuf", "-u", f"{self.target_url}/FUZZ", "-w", wordlist, "-mc", "200", "-s"])

    async def run_dirsearch(self):
        return await self._run_docker_cmd(["dirsearch", "-u", self.target_url, "-e", "php,html,txt", "-s"])

    # --- HERRAMIENTAS DE EXPLOTACIÓN ---
    async def run_sqlmap(self, url: str, param: str):
        """Automatiza la inyección SQL."""
        return await self._run_docker_cmd(["sqlmap", "-u", f"{url}?{param}=1", "--batch", "--random-agent", "--level=1"])

    async def run_commix(self, url: str, param: str):
        """Automatiza la inyección de comandos (RCE)."""
        return await self._run_docker_cmd(["commix", "--url", f"{url}?{param}=1", "--batch"])

    # --- POST-EXPLOTACIÓN ---
    async def run_linpeas(self):
        """Busca rutas de escalada de privilegios."""
        return await self._run_docker_cmd(["/tmp/linpeas.sh"])

recon_pro = ReconToolsPro
