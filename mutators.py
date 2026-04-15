import random
import re
import urllib.parse
from typing import Dict, Iterable, List


def apply_hex_encode(payload: str) -> str:
    """Representa el texto en hexadecimal para auditoria de normalizacion."""
    return "".join([f"\\x{ord(c):02x}" for c in payload])


def apply_inline_comments(payload: str) -> str:
    """Inserta separadores inline para comprobar si el filtro reconstruye tokens."""
    words = payload.split()
    mutated = "/**/".join(words)
    keywords = ["SELECT", "UNION", "WHERE", "FROM", "INSERT", "DELETE", "UPDATE", "INFORMATION_SCHEMA"]
    for keyword in keywords:
        if keyword in mutated.upper():
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            mutated = pattern.sub(lambda m: f"{m.group(0)[:3]}/**/{m.group(0)[3:]}", mutated)
    return mutated


def apply_case_variation(payload: str) -> str:
    """Varia mayusculas para probar normalizacion case-insensitive."""
    return "".join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])


def apply_url_double_encode(payload: str) -> str:
    """Conservado por compatibilidad retroactiva."""
    first = urllib.parse.quote(payload)
    return urllib.parse.quote(first)


def apply_null_byte_injection(payload: str) -> str:
    """Conservado por compatibilidad retroactiva."""
    return payload.replace(" ", "%00 ") + "%00"


def mutate_payload(payload: str, strategy: str) -> str:
    """Dispatcher maestro de variantes de texto."""
    strategies = {
        "HEX_ENCODE": apply_hex_encode,
        "INLINE_COMMENTS": apply_inline_comments,
        "CASE_VARIATION": apply_case_variation,
        "URL_DOUBLE_ENCODE": apply_url_double_encode,
        "NULL_BYTE_INJECTION": apply_null_byte_injection,
    }
    func = strategies.get(strategy, apply_inline_comments)
    return func(payload)


def build_filter_audit_variants(sample_text: str, strategies: Iterable[str] | None = None) -> Dict[str, str]:
    """Genera variantes inofensivas para comparar la normalizacion del filtro."""
    selected = list(strategies or ["HEX_ENCODE", "INLINE_COMMENTS", "CASE_VARIATION"])
    return {strategy: mutate_payload(sample_text, strategy) for strategy in selected}


def extract_blocked_keywords(log_text: str) -> List[str]:
    """Extrae mensajes, ids y matched data de logs para evidencia defensiva."""
    findings: List[str] = []
    patterns = [
        r"Matched Data:\s*(.+?)(?:\s+\[|$)",
        r"\[msg \"([^\"]+)\"\]",
        r"\[data \"([^\"]+)\"\]",
        r"\[id \"([^\"]+)\"\]",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, log_text, flags=re.IGNORECASE | re.DOTALL):
            cleaned = " ".join(str(match).split())
            if cleaned and cleaned not in findings:
                findings.append(cleaned)
    return findings
