import docker
import logging
import re
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

# Configuración de Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ArtOfIA-Executor")

class ToolRequest(BaseModel):
    tool: str = Field(..., description="Nombre de la herramienta (ej: sqlmap, nmap)")
    arguments: str = Field(..., description="Argumentos de la herramienta con tokens simbólicos")
    timeout: int = 300  # 5 minutos por defecto

class ToolExecutor:
    def __init__(self, container_name: str = "ai-worker"):
        self.client = docker.from_env()
        self.container_name = container_name
        # Whitelist de herramientas permitidas para evitar RCE en el host
        self.allowed_tools = {
            "nmap": {"binary": "nmap", "critical_flags": ["-sU"]}, # Ejemplo: bloquear UDP scan si es lento
            "sqlmap": {"binary": "sqlmap", "critical_flags": ["--os-shell"]}, # Prohibido shell remoto por seguridad
            "commix": {"binary": "commix", "critical_flags": []},
            "dirsearch": {"binary": "dirsearch", "critical_flags": []},
            "gobuster": {"binary": "gobuster", "critical_flags": []},
            "ffuf": {"binary": "ffuf", "critical_flags": []},
        }

    def _resolve_symbols(self, arguments: str, symbol_map: Dict[str, Any]) -> str:
        """
        Traduce $SQL_VAR_1 -> 'admin\'--' 
        Utiliza el mapa de símbolos mantenido por el Symbolic Controller.
        """
        resolved_args = arguments
        for symbol, value in symbol_map.items():
            resolved_args = resolved_args.replace(symbol, str(value))
        return resolved_args

    def _validate_command(self, tool: str, resolved_args: str) -> bool:
        """Valida que la herramienta esté permitida y no contenga flags prohibidos o inyecciones de shell."""
        if tool not in self.allowed_tools:
            logger.error(f"Tool {tool} is not in the whitelist.")
            return False
        
        # Evitar encadenamiento de comandos (; && |)
        if any(char in resolved_args for char in [';', '&&', '||', '`']):
            logger.error("Command injection detected in arguments.")
            return False

        # Validar flags críticos
        critical_flags = self.allowed_tools[tool]["critical_flags"]
        for flag in critical_flags:
            if flag in resolved_args:
                logger.error(f"Critical flag {flag} is forbidden for tool {tool}.")
                return False
        
        return True

    def execute(self, request: ToolRequest, symbol_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orquestador de ejecución: Resolve $\rightarrow$ Validate $\rightarrow$ Run $\rightarrow$ Sanitize
        """
        try:
            # 1. Resolución de Símbolos
            resolved_args = self._resolve_symbols(request.arguments, symbol_map)
            
            # 2. Validación
            if not self._validate_command(request.tool, resolved_args):
                return {"status": "error", "message": "Security validation failed."}

            # 3. Ejecución en Docker
            container = self.client.containers.get(self.container_name)
            binary = self.allowed_tools[request.tool]["binary"]
            full_command = f"{binary} {resolved_args}"
            
            logger.info(f"Executing in {self.container_name}: {full_command}")
            
            # Ejecutar comando y capturar salida
            exit_code, output = container.exec_run(
                cmd=full_command, 
                user="root", # O el usuario definido en el Dockerfile
                environment={"TERM": "xterm"}
            )

            # 4. Post-procesamiento de salida
            output_text = output.decode('utf-8')
            return {
                "status": "success" if exit_code == 0 else "completed_with_errors",
                "exit_code": exit_code,
                "raw_output": self._sanitize_output(output_text),
                "command_executed": full_command
            }

        except Exception as e:
            logger.exception("Execution error")
            return {"status": "error", "message": str(e)}

    def _sanitize_output(self, text: str) -> str:
        """
        Limpia el output para el LLM:
        - Elimina líneas repetitivas (estilo progress bars de sqlmap)
        - Trunca outputs excesivamente largos
        """
        # Eliminar líneas de progreso/estética (ej: [***] updating target...)
        lines = text.splitlines()
        filtered_lines = [line for line in lines if not line.startswith('[***]')]
        
        final_text = "\n".join(filtered_lines)
        # Truncar a 4000 caracteres para no reventar el contexto del LLM
        return final_text[:4000] + "... [Truncated]" if len(final_text) > 4000 else final_text
