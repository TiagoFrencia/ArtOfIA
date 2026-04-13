import asyncio
from typing import Dict, Any, Callable, Type
from pydantic import BaseModel, Field, ValidationError
from temporalio import activity
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

# ---------------------------------------------------------
# OPEN TELEMETRY TRACER
# ---------------------------------------------------------
tracer = trace.get_tracer("agent.executor")

# ---------------------------------------------------------
# HASHICORP VAULT STUB (Zero Trust)
# ---------------------------------------------------------
class HashiCorpVaultClient:
    """
    Cliente para solicitar tokens efímeros justo en tiempo de ejecución (JIT).
    Previene que el agente retenga credenciales estáticas.
    """
    @staticmethod
    async def get_ephemeral_token(role: str) -> str:
        # En producción usar: hvac.AsyncClient(url=VAULT_ADDR)
        return f"mcp_vault_token_{role}_active"

# ---------------------------------------------------------
# INPUT VALIDATION SCHEMAS (Action-Selector Pattern)
# ---------------------------------------------------------
# NUNCA aceptar texto libre. Todo debe calzar en Pydantic.

class ActionParams(BaseModel):
    """Clase base para parámetros fuertemente tipados."""
    pass

class NmapParams(ActionParams):
    target_ip: str = Field(..., pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", description="IPv4 válida obligatoria")
    ports: str = Field(default="80,443", pattern=r"^[0-9,]+$", description="Lista de puertos CSV")

class HttpParams(ActionParams):
    endpoint: str = Field(..., pattern=r"^https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9_.-]+)*$", description="URL segura")
    method: str = Field(default="GET", pattern=r"^(GET|POST|HEAD)$")

# ---------------------------------------------------------
# HARDCODED PREDEFINED TOOLS
# ---------------------------------------------------------
# Las herramientas NUNCA usan concatenación de strings para el shell (previene inyección).

@activity.defn
async def run_nmap(params: NmapParams) -> str:
    """Ejecución de nmap validada puramente por parámetros estructurados."""
    with tracer.start_as_current_span("tool.run_nmap") as span:
        span.set_attribute("target", params.target_ip)
        span.set_attribute("ports", params.ports)
        
        # En producción, se invoca vía subprocess de red sin shell=True.
        # Aquí solo simulamos el resultado seguro.
        result = f"Obtained open ports on {params.target_ip}: {params.ports}"
        span.add_event("Scan completed")
        return result

@activity.defn
async def fetch_http(params: HttpParams) -> str:
    """Petición HTTP estricta a un endpoint."""
    with tracer.start_as_current_span("tool.fetch_http") as span:
        span.set_attribute("endpoint", params.endpoint)
        span.set_attribute("method", params.method)
        
        # En producción usar httpx AsyncClient
        return f"{params.method} success against {params.endpoint}"

# ---------------------------------------------------------
# TOOL REGISTRY
# ---------------------------------------------------------
class ToolRegistry:
    """Registro estricto de herramientas permitidas."""
    
    _registry: Dict[str, Dict[str, Any]] = {
        "nmap_scan": {
            "schema": NmapParams,
            "executable": run_nmap,
            "requires_auth": False
        },
        "http_request": {
            "schema": HttpParams,
            "executable": fetch_http,
            "requires_auth": True
        }
    }

    @classmethod
    def get_tool(cls, action_name: str):
        if action_name not in cls._registry:
            raise ValueError(f"Acción '{action_name}' desconocida o prohibida.")
        return cls._registry[action_name]

# ---------------------------------------------------------
# TEMPORAL EXECUTOR
# ---------------------------------------------------------
class TemporalExecutor:
    """
    Componente Ejecutor Seguro (E) para la arquitectura P-E-R.
    Validación tipada -> Autenticación JIT -> Ejecución Aislada -> Trazabilidad OTel.
    """
    
    def __init__(self):
        self.vault = HashiCorpVaultClient()

    @activity.defn(name="SafeToolCaller")
    async def execute_action(self, action_name: str, raw_params: Dict[str, Any]) -> str:
        """
        Actividad de Temporal con control de timeout y reintentos (manejados por Temporal Worker).
        """
        with tracer.start_as_current_span("executor.run_action") as span:
            span.set_attribute("action", action_name)
            
            try:
                # 1. Recuperar herramienta cruda del registro
                tool_spec = ToolRegistry.get_tool(action_name)
                SchemaClass: Type[ActionParams] = tool_spec["schema"]
                ToolFunc: Callable = tool_spec["executable"]
                
                # 2. Validación Estricta de Parámetros (Zero-Trust)
                span.add_event("Validating Input")
                validated_params = SchemaClass(**raw_params)
                
                # 3. Autenticación JIT con Vault (Solo si es requerida por la acción)
                auth_token = None
                if tool_spec["requires_auth"]:
                    span.add_event("Requesting Ephemeral HashiCorp Vault Token")
                    auth_token = await self.vault.get_ephemeral_token(role="mcp_execution_role")
                    # En producción: Inyectar auth_token en la sesión HTTP/MCP o pasarlo de largo.
                
                # 4. Ejecución de la Actividad (Sin comandos shell crudos)
                span.add_event("Invoking Hardcoded Executable")
                
                # Para evitar doble actividad anidada indeseada por Temporal (si la sub-función
                # ya usaba @activity.defn), dependería de cómo registras las activities.
                # Aquí la invocamos directamente para simplificar.
                result = await ToolFunc(validated_params)
                
                span.set_status(Status(StatusCode.OK))
                return result
                
            except ValidationError as e:
                # Sanitizar el esquema ante el agente LLM
                err_msg = f"Rechazo de Validación: {e.errors()}"
                span.set_status(Status(StatusCode.ERROR, err_msg))
                # Temporal automáticamente registrará la falla Activity y, dependiendo el policy, fallará
                raise Exception(err_msg)
            
            except Exception as e:
                err_msg = f"Falla de Ejecución: {str(e)}"
                span.set_status(Status(StatusCode.ERROR, err_msg))
                raise Exception(err_msg)

# ---------------------------------------------------------
# USO DE PRUEBA (SOLO PARA DEMOSTRACIÓN)
# ---------------------------------------------------------
async def __demo_execution():
    executor = TemporalExecutor()
    
    # Intento 1: Llamada Exitosa
    print("Prueba 1: Input Válido")
    res1 = await executor.execute_action(
        "http_request", 
        {"endpoint": "https://api.github.com", "method": "GET"}
    )
    print("Salida:", res1)
    
    # Intento 2: Prevención de Inyección o input malicioso
    print("\nPrueba 2: Prevención Pydantic (Input Inválido/Inyección)")
    try:
        await executor.execute_action(
            "nmap_scan", 
            {"target_ip": "192.168.1.1; rm -rf /", "ports": "80"}
        )
    except Exception as e:
        print("El Ejecutor bloqueó satisfactoriamente la llamada:", str(e)[:150], "...")

if __name__ == "__main__":
    asyncio.run(__demo_execution())
