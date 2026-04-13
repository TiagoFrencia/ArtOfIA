import asyncio
from typing import Tuple, Dict, Any
import redis.asyncio as redis
from opentelemetry import metrics

# ---------------------------------------------------------
# OPEN TELEMETRY METRICS CONFIGURATION
# ---------------------------------------------------------
# Requisito: Métrica custom "cost per vulnerability found"
meter = metrics.get_meter("agent.cost_manager")

# Histogramas y Contadores para monitoreo activo
vuln_cost_histogram = meter.create_histogram(
    "cost_per_vulnerability_found", 
    description="Trackea el USD consumido por cada vulnerabilidad confirmada",
    unit="USD"
)
usd_spent_counter = meter.create_counter(
    "total_usd_spent", 
    description="Acumulador de gasto total"
)

# ---------------------------------------------------------
# REDIS-BACKED COST MANAGER
# ---------------------------------------------------------
class CostManager:
    """
    Controlador Asíncrono de Costos y Recursos para la capa Reflector.
    Basado en Redis para persistencia atómica en microservicios (Temporal Workers multimodelo).
    """
    
    def __init__(self, trace_id: str, redis_url: str = "redis://localhost:6379"):
        """
        :param trace_id: El ID de sesión que encapsula y agrupa la métrica conjunta de un agente.
        """
        self.trace_id = trace_id
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.MAX_USD_COST = 0.30
        
        # Redis Key structure
        self.k_cost = f"agent:{trace_id}:cost"
        self.k_tokens = f"agent:{trace_id}:tokens"
        self.k_tools = f"agent:{trace_id}:tool_calls"
        self.k_success = f"agent:{trace_id}:successes"
        
    async def log_usage(self, usd_cost: float, tokens: int, is_tool_call: bool = False) -> None:
        """
        Actualización Atómica del consumo en el Shared Datastore.
        """
        # Pipeline para reducir latencia de red
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incrbyfloat(self.k_cost, usd_cost)
            pipe.incrby(self.k_tokens, tokens)
            if is_tool_call:
                pipe.incrby(self.k_tools, 1)
            await pipe.execute()
            
        # Emitir telemetría OpenTelemetry
        usd_spent_counter.add(usd_cost, {"trace_id": self.trace_id})

    async def get_stats(self) -> Dict[str, float]:
        """Obtiene el estado actual unificado desde Redis."""
        # Se requiere coalesce para las claves que aún no existen
        results = await self.redis.mget(self.k_cost, self.k_tokens, self.k_tools, self.k_success)
        return {
            "usd_cost": float(results[0] or 0.0),
            "tokens": int(results[1] or 0),
            "tool_calls": int(results[2] or 0),
            "successes": int(results[3] or 0)
        }

    async def should_continue(self) -> Tuple[bool, str]:
        """
        API Estricta expuesta para que el nodo REFLECTOR tome decisiones duras de límite.
        """
        stats = await self.get_stats()
        
        if stats["usd_cost"] >= self.MAX_USD_COST:
            return False, f"Umbral financiero excedido. USD ${stats['usd_cost']:.2f} >= ${self.MAX_USD_COST:.2f}"
            
        return True, "Presupuesto operativo saludable."

    async def record_vulnerability_found(self) -> None:
        """
        Debe ser llamado cuando el Agent confirma validación (Ej. WAF evasion success).
        """
        stats = await self.get_stats()
        
        # Aumentar success count
        await self.redis.incrby(self.k_success, 1)
        
        # Emitir la métrica clave requerida para observabilidad L4
        # Atribuimos el costo acumulado de TODO el rastreo hasta el instante del hallazgo
        vuln_cost_histogram.record(stats["usd_cost"], {"trace_id": self.trace_id, "type": "vulnerability_found"})
        print(f"[Telemetría] Vulnerabilidad confirmada insertada: ${stats['usd_cost']:.4f} costo total de descubrimiento.")

    async def cost_per_success(self) -> float:
        """
        KPI Retrospectivo: USD invertido / vulnerabilidades explotadas exitosamente.
        """
        stats = await self.get_stats()
        if stats["successes"] == 0:
            return float("inf")  # Costo teórico infinito si gastamos sin éxito
            
        return stats["usd_cost"] / stats["successes"]

# ---------------------------------------------------------
# DEMONSTRATION SCRIPT
# ---------------------------------------------------------
async def __demo():
    print("Iniciando Gestor de Costos (Emulación Async)...")
    # Para la simulación fallamos graciosamente si redis no corre,
    # en producción Temporal.io manejará el runtime
    try:
        # Mock connection or pass fake client in tests
        manager = CostManager(trace_id="exec_9b3z_x1")
        
        await manager.log_usage(usd_cost=0.05, tokens=1500, is_tool_call=True)
        await manager.log_usage(usd_cost=0.10, tokens=3000, is_tool_call=False)
        
        # Evaluar Reflector
        can_cont, reason = await manager.should_continue()
        print(f"Estado Autorización (Límite ${manager.MAX_USD_COST}): {can_cont} -> {reason}")
        
        # Explotación exitosa
        await manager.record_vulnerability_found()
        
        # Check Final KPI
        kpi = await manager.cost_per_success()
        print(f"\nKPI Evaluado - Cost Per Success: ${kpi:.4f}")
        
        # Forzar Límite
        await manager.log_usage(usd_cost=0.20, tokens=6000, is_tool_call=True)
        can_cont_2, reason_2 = await manager.should_continue()
        print(f"\nEstado Autorización tras Gasto Excesivo: {can_cont_2} -> {reason_2}")
        
    except redis.exceptions.ConnectionError:
        print("\n[!] Redis no está corriendo localmente en el docker host. Instanciación estructural validada.")

if __name__ == "__main__":
    asyncio.run(__demo())
