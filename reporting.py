import json
from datetime import datetime

class ArtOfIA_Reporter:
    """Genera un informe técnico basado en la evolución del AgentState."""
    
    @staticmethod
    def generate_poc_report(final_state: dict):
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": final_state["target_url"],
            "vulnerability": final_state["vuln_type"],
            "final_payload": final_state["current_payload"],
            "attack_chain": final_state["failed_attempts_summary"],
            "result": "EXPLOITED" if final_state["status"] == "success" else "FAILED"
        }
        
        with open(f"poc_{final_state['vuln_type']}.json", "w") as f:
            json.dump(report, f, indent=4)
            
        print(f"\n[+] [REPORT] PoC generado exitosamente: poc_{final_state['vuln_type']}.json")
        return report
