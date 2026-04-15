from knowledge_base import kb

# Aquí simulamos la ingesta de HackTricks y PayloadsAllTheThings
# En una versión Pro, esto leería archivos .md o .txt automáticamente
knowledge_data = [
    {
        "id": "sql_inline_comments",
        "content": "Para bypass de ModSecurity Rule 942100 (SQLi), usar comentarios inline como 'SEL/**/ECT' o 'UNI/**/ON'.",
        "meta": {"vuln": "SQLI", "waf": "ModSecurity"}
    },
    {
        "id": "lfi_null_byte",
        "content": "En PHP < 5.3.4, el Null Byte (%00) corta el string y permite ignorar la extensión forzada del servidor.",
        "meta": {"vuln": "LFI", "waf": "Generic"}
    },
    {
        "id": "xss_svg_onload",
        "content": "Cuando <script> está prohibido, usar <svg/onload=alert(1)> para ejecutar JS en navegadores modernos.",
        "meta": {"vuln": "XSS", "waf": "Cloudflare"}
    },
    {
        "id": "sqli_case_variation",
        "content": "Si el WAF es case-insensitive pero el backend no, usar variaciones como 'uNiOn sElEcT'.",
        "meta": {"vuln": "SQLI", "waf": "Generic"}
    }
]

def seed():
    print("[*] Cargando sabiduría en la Vector DB...")
    for item in knowledge_data:
        kb.add_tactic(item["id"], item["content"], item["meta"])
    print("[+] Base de conocimiento inicializada con éxito.")

if __name__ == "__main__":
    seed()
