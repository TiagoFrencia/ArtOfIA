# Arquitectura base para sistemas autonomos con sandbox multi-LLM

Este proyecto crea una base funcional para experimentar con agentes autonomos de forma mas segura:

- `socket-proxy`: filtra el acceso a Docker y evita exponer `docker.sock` directamente.
- `brain`: servidor FastAPI con WebSocket, frontend y enrutamiento de prompts.
- `worker`: sandbox de Kali Linux donde vive la terminal remota.

## 1. Alcance y Estado del Proyecto (Base vs Deuda Técnica)

Este proyecto nace como una base ambiciosa de arquitectura P-E-R (Planner-Executor-Reflector) usando agentes duales y LangGraph. Actualmente el repositorio se encuentra en despliegue iterativo.

### Implementado
- **Aislamiento Base**: Filtros al socket de Docker (`socket-proxy`), contenedor `worker` (Kali) aislado y `brain` como orquestador / WebSocket server.
- **Workflow P-E-R Conceptual**: Nodos base mapeados en `main_orchestrator.py` utilizando NetworkX/LangGraph.
- **Dual-LLM Pattern Conceptual**: Separación en `dual_llm_pattern.py` entre LLM Cuarentena y Privilegiado.

### Deuda Técnica Parcial (Backlog Actual)
- **Desconexión entre módulos**: El `brain` y el Loop de LangGraph no están integrados en su `/route`.
- **Nodos Vacíos**: Los nodos L1 a L4 y el executor de LangGraph actualmente son stubs con mockeo.
- **Déficit de Persistencia**: Aún no cuenta con la conexión real a `pgvector` que indica la fase de arquitectura (reemplazada por archivos TXT temporales momentáneamente).
- **Cobertura de Pruebas**: Ausencia de tests estructurados para validación XBOW.

## 2. Flujo Básico Actual

El flujo de conexión interactiva:

1. El navegador se conecta al servicio `brain`.
2. `brain` abre una shell interactiva dentro del contenedor `worker`.
3. Todo lo que se escribe en la terminal viaja por WebSocket.
4. El `worker` ejecuta el comando dentro del sandbox.
5. La salida vuelve en tiempo real a la interfaz web.

Ademas, el endpoint `POST /route` deja preparado un esquema de delegacion:

- `analyze_logs`: usa el modelo local via Ollama para resumir datos grandes.
- `plan_next_command`: usa Gemini por API para decidir el siguiente paso.

Por defecto, esta base intenta usar `ollama/gemma4:26b` y, si falla por memoria, cae automaticamente a `ollama/gemma3:12b`.
La ruta de nube queda apuntando a `gemini/gemini-2.5-flash`.

## 2. Estructura del proyecto

```text
.
|-- docker-compose.yml
|-- .env.example
|-- brain/
|   |-- Dockerfile
|   |-- requirements.txt
|   `-- app/
|       |-- main.py
|       `-- static/
|           |-- index.html
|           |-- app.js
|           `-- styles.css
`-- worker/
    `-- Dockerfile
```

## 3. Requisitos previos

Necesitas:

- Docker Desktop instalado.
- WSL2 habilitado si estas en Windows.
- Ollama instalado en la maquina anfitriona si quieres usar el modelo local.
- Una API key de Gemini si quieres usar la ruta de nube.

## 4. Como levantar el proyecto

### Paso 1: copiar variables opcionales

Si quieres personalizar modelos o agregar claves:

```powershell
Copy-Item .env.example .env
```

Despues edita `.env` y agrega tu clave:

```env
GEMINI_API_KEY=tu_clave_real
```

### Paso 2: construir los contenedores

```powershell
docker compose build
```

### Paso 3: iniciar la arquitectura

```powershell
docker compose up
```

Luego abre:

- [http://localhost:8000](http://localhost:8000)

## 5. Que medidas de aislamiento ya incluye

- El `worker` no monta carpetas del host.
- El `worker` esta en una red `internal: true`, sin salida a Internet.
- El `worker` no recibe capacidades Linux extra.
- Se activa `no-new-privileges`.
- El acceso a Docker pasa por `socket-proxy` y no por `docker.sock` directo.
- El `worker` usa `tmpfs` para `/tmp` y tiene limites de CPU y memoria.

## 6. Limitaciones importantes

Esta es una base segura, no una garantia absoluta:

- Un contenedor sigue compartiendo kernel con el host.
- Kali Linux es potente, pero tambien amplia superficie de paquetes.
- Para aislamiento mas fuerte, el siguiente paso seria microVMs como Firecracker.
- El proxy actual permite operaciones de `exec`; si amplias permisos, revisa el riesgo.

## 7. Prueba rapida del WebSocket

Cuando abras la UI deberias ver el mensaje:

```text
[brain] sesion conectada al worker 'ai-worker'
```

Despues puedes escribir:

```bash
whoami
pwd
uname -a
```

Todo debe ejecutarse dentro del contenedor de Kali.

## 8. Uso del enrutamiento hibrido

### Analisis local

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8000/route `
  -ContentType "application/json" `
  -Body '{"task":"analyze_logs","content":"ERROR 500 en linea 200..."}'
```

### Planificacion en nube

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8000/route `
  -ContentType "application/json" `
  -Body '{"task":"plan_next_command","content":"Se detecto que nginx no arranca por un error de sintaxis en la linea 40 del archivo de configuracion."}'
```

## 8.1 Verificacion de estado de modelos

- `GET /health`: muestra si la ruta local y la ruta de nube estan configuradas.
- `GET /models/local`: lista los modelos de Ollama visibles desde el contenedor `brain`.

## 9. Siguiente fase recomendada

Si quieres llevarlo a una version mas cercana a produccion, el orden recomendado es:

1. Agregar autenticacion a la UI y al WebSocket.
2. Registrar sesiones, comandos y auditoria.
3. Restringir aun mas los comandos permitidos.
4. Separar un servicio Ollama dedicado con GPU.
5. Evaluar microVMs o un host remoto desechable para tareas de mayor riesgo.
