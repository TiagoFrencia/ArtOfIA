from mutators import mutate_payload

def test_visual():
    payload = "admin' OR '1'='1"
    strategies = ['HEX_ENCODE', 'INLINE_COMMENTS', 'CASE_VARIATION', 'URL_DOUBLE_ENCODE', 'NULL_BYTE_INJECTION']
    
    print("="*60)
    print(f"TEST DE MUTACIÓN LOCAL (ArtofIA Sniper Engine)")
    print(f"Payload Original: {payload}")
    print("="*60)
    
    for strategy in strategies:
        mutated = mutate_payload(payload, strategy)
        print(f"[{strategy:^20}] -> {mutated}")
    
    print("="*60)
    print("Resultado: El orquestador ahora dispara estas funciones Python")
    print("según la decisión estratégica del modelo local Qwen.")
    print("="*60)

if __name__ == "__main__":
    test_visual()
