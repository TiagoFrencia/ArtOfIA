import base64
import urllib.parse
import logging

logger = logging.getLogger("ArtOfIA-Polymorphic")

class PolymorphicBridge:
    """
    Dynamic Encoder Bridge.
    Permite encadenar transformaciones de payloads para evadir IDS/IPS y WAFs.
    """
    def __init__(self):
        # Diccionario de funciones de codificación atómicas
        self.encoders = {
            "URL_ENCODE": self._url_encode,
            "DOUBLE_URL_ENCODE": lambda x: self._url_encode(self._url_encode(x)),
            "HEX_ENCODE": self._hex_encode,
            "BASE64_ENCODE": self._base64_encode,
            "UNICODE_ESCAPE": self._unicode_escape,
            "NULL_BYTE": self._null_byte_inject,
            "CASE_SQUASH": self._case_squash
        }

    # --- IMPLEMENTACIONES ATÓMICAS ---
    def _url_encode(self, text: str) -> str:
        return urllib.parse.quote(text)

    def _hex_encode(self, text: str) -> str:
        return "".join([f"\\x{ord(c):02x}" for c in text])

    def _base64_encode(self, text: str) -> str:
        return base64.b64encode(text.encode()).decode()

    def _unicode_escape(self, text: str) -> str:
        return text.encode('unicode_escape').decode()

    def _null_byte_inject(self, text: str) -> str:
        return f"{text}\x00"

    def _case_squash(self, text: str) -> str:
        # Alterna mayúsculas y minúsculas para evadir filtros de palabras clave (S-e-L-e-C-t)
        return "".join([char.upper() if i % 2 == 0 else char.lower() for i, char in enumerate(text)])

    def apply_chain(self, payload: str, chain: list) -> str:
        """
        Aplica una serie de codificaciones en el orden especificado.
        Ej: ['CASE_SQUASH', 'URL_ENCODE', 'DOUBLE_URL_ENCODE']
        """
        current_payload = payload
        logger.info(f"[PolyBridge] Applying chain: {chain} to payload")
        
        for step in chain:
            if step in self.encoders:
                current_payload = self.encoders[step](current_payload)
            else:
                logger.warning(f"[PolyBridge] Unknown encoder: {step}. Skipping.")
        
        return current_payload

# Singleton para integración
poly_bridge = PolymorphicBridge()
