import asyncio
import contextlib
import os
import socket as pysocket
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import docker
from docker.errors import APIError, NotFound
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from litellm import completion


app = FastAPI(title="AI Sandbox Brain", version="0.1.0")
app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")

executor = ThreadPoolExecutor(max_workers=8)
docker_client = docker.DockerClient(base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))
docker_api = docker.APIClient(base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

WORKER_CONTAINER = os.getenv("WORKER_CONTAINER", "ai-worker")
HEARTBEAT_SECONDS = int(os.getenv("HEARTBEAT_SECONDS", "25"))
LOCAL_MODEL = os.getenv("LOCAL_MODEL", "ollama/gemma4:26b")
LOCAL_FALLBACK_MODEL = os.getenv("LOCAL_FALLBACK_MODEL", "ollama/gemma3:12b")
CLOUD_MODEL = os.getenv("CLOUD_MODEL", "gemini/gemini-2.5-flash")
OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse("/app/app/static/index.html")


@app.get("/health")
async def health() -> JSONResponse:
    try:
        container = docker_client.containers.get(WORKER_CONTAINER)
        status = container.status
    except Exception as exc:  # pragma: no cover - health endpoint best effort
        status = f"unavailable: {exc}"

    return JSONResponse(
        {
            "status": "ok",
            "worker_container": WORKER_CONTAINER,
            "worker_status": status,
            "local_model": LOCAL_MODEL,
            "local_fallback_model": LOCAL_FALLBACK_MODEL,
            "cloud_model": CLOUD_MODEL,
            "cloud_provider_ready": bool(GEMINI_API_KEY),
        }
    )


@app.get("/models/local")
async def local_models() -> JSONResponse:
    try:
        payload = await asyncio.to_thread(fetch_ollama_models)
        return JSONResponse(payload)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"No se pudo consultar Ollama: {exc}") from exc


def get_worker_container():
    try:
        return docker_client.containers.get(WORKER_CONTAINER)
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=f"Worker container '{WORKER_CONTAINER}' no encontrado") from exc


def create_exec_socket() -> tuple[str, pysocket.socket]:
    container = get_worker_container()
    exec_id = docker_api.exec_create(
        container.id,
        cmd=["/bin/bash"],
        stdin=True,
        tty=True,
        environment={"TERM": "xterm-256color"},
    )["Id"]
    raw_socket = docker_api.exec_start(exec_id, socket=True, tty=True, detach=False)
    return exec_id, raw_socket._sock


async def read_terminal_output(websocket: WebSocket, sock: pysocket.socket, stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    def blocking_read() -> bytes:
        try:
            return sock.recv(4096)
        except OSError:
            return b""

    while not stop_event.is_set():
        data = await loop.run_in_executor(executor, blocking_read)
        if not data:
            break
        await websocket.send_text(data.decode("utf-8", errors="replace"))


async def heartbeat(websocket: WebSocket, stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        await asyncio.sleep(HEARTBEAT_SECONDS)
        if stop_event.is_set():
            return
        await websocket.send_text("\r\n[heartbeat] conexion activa\r\n")


@app.websocket("/ws")
async def terminal_ws(websocket: WebSocket) -> None:
    await websocket.accept()

    stop_event = asyncio.Event()
    exec_id: Optional[str] = None
    sock: Optional[pysocket.socket] = None
    reader_task: Optional[asyncio.Task] = None
    heartbeat_task: Optional[asyncio.Task] = None

    try:
        exec_id, sock = create_exec_socket()
        sock.setblocking(True)
        reader_task = asyncio.create_task(read_terminal_output(websocket, sock, stop_event))
        heartbeat_task = asyncio.create_task(heartbeat(websocket, stop_event))
        await websocket.send_text(f"[brain] sesion conectada al worker '{WORKER_CONTAINER}'\r\n")

        while True:
            message = await websocket.receive_text()
            if message == "__ping__":
                await websocket.send_text("__pong__")
                continue

            if message.startswith("__resize__:"):
                parts = message.split(":")
                if len(parts) == 3:
                    try:
                        cols = int(parts[1])
                        rows = int(parts[2])
                        docker_api.exec_resize(exec_id, height=rows, width=cols)
                    except (ValueError, APIError):
                        await websocket.send_text("\r\n[brain] no se pudo redimensionar la terminal\r\n")
                continue

            if sock is not None:
                sock.send(message.encode("utf-8", errors="ignore"))

    except WebSocketDisconnect:
        pass
    except (APIError, HTTPException) as exc:
        await websocket.send_text(f"\r\n[brain] error docker: {exc}\r\n")
    finally:
        stop_event.set()
        if heartbeat_task:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task
        if reader_task:
            with contextlib.suppress(asyncio.CancelledError):
                await reader_task
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()
        with contextlib.suppress(RuntimeError):
            await websocket.close()


@app.post("/route")
async def route_prompt(payload: dict) -> JSONResponse:
    task = payload.get("task", "").strip()
    content = payload.get("content", "").strip()

    if not task or not content:
        raise HTTPException(status_code=400, detail="Debes enviar 'task' y 'content'")

    if task == "analyze_logs":
        try:
            response = await asyncio.to_thread(call_local_model_with_fallback, content)
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Fallo la ruta local hacia Ollama. "
                    f"Modelo principal: '{LOCAL_MODEL}'. Modelo fallback: '{LOCAL_FALLBACK_MODEL}'. Error: {exc}"
                ),
            ) from exc
        return JSONResponse(response)

    if task == "plan_next_command":
        try:
            response = await asyncio.to_thread(call_cloud_model, content)
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Fallo la ruta de nube. "
                    f"Modelo configurado: '{CLOUD_MODEL}'. Verifica tu GEMINI_API_KEY. Error: {exc}"
                ),
            ) from exc
        return JSONResponse({"route": "cloud", "model": CLOUD_MODEL, "response": response})

    raise HTTPException(status_code=400, detail=f"Tarea desconocida: {task}")


def call_local_model(content: str) -> str:
    return call_local_model_for_model(LOCAL_MODEL, content)


def call_local_model_for_model(model_name: str, content: str) -> str:
    kwargs = {}
    if OLLAMA_API_BASE:
        kwargs["api_base"] = OLLAMA_API_BASE

    response = completion(
        model=model_name,
        messages=[
            {
                "role": "system",
                "content": (
                    "Eres un analista local. Resume logs extensos, elimina secretos y devuelve solo hallazgos criticos."
                ),
            },
            {"role": "user", "content": content},
        ],
        **kwargs,
    )
    return response.choices[0].message.content


def call_local_model_with_fallback(content: str) -> dict:
    try:
        return {
            "route": "local",
            "model": LOCAL_MODEL,
            "response": call_local_model_for_model(LOCAL_MODEL, content),
            "fallback_used": False,
        }
    except Exception as exc:
        memory_error = "requires more system memory" in str(exc) or "not enough memory" in str(exc).lower()
        if not memory_error or not LOCAL_FALLBACK_MODEL or LOCAL_FALLBACK_MODEL == LOCAL_MODEL:
            raise

        return {
            "route": "local",
            "model": LOCAL_FALLBACK_MODEL,
            "response": call_local_model_for_model(LOCAL_FALLBACK_MODEL, content),
            "fallback_used": True,
            "fallback_reason": str(exc),
        }


def fetch_ollama_models() -> dict:
    import json
    import urllib.request

    if not OLLAMA_API_BASE:
        raise RuntimeError("OLLAMA_API_BASE no esta configurado")

    with urllib.request.urlopen(f"{OLLAMA_API_BASE}/api/tags") as response:
        return json.loads(response.read().decode("utf-8"))


def call_cloud_model(summary: str) -> str:
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY no esta configurada")

    response = completion(
        model=CLOUD_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "Eres un estratega de operaciones en un sandbox de Linux. "
                    "Responde con el siguiente comando recomendado y una breve justificacion."
                ),
            },
            {"role": "user", "content": summary},
        ],
        api_key=GEMINI_API_KEY,
    )
    return response.choices[0].message.content
