import json
import re
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict, ValidationError
from neo4j import GraphDatabase
import os

# Intentamos importar la función del proyecto, o usamos un mock local
try:
    from litellm import completion
    
    def call_llm_api(prompt: str) -> str:
        model = os.getenv("CLOUD_MODEL", "gemini/gemini-2.5-flash")
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return '{"horizon_estimation": 0.4, "evidence_confidence": 0.8, "context_load": 0.3, "historical_success": 0.6}'
        print(f"[Planner] Llamando al modelo real: {model}")
        response = completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            api_key=api_key
        )
        return response.choices[0].message.content
except ImportError:
    def call_llm_api(prompt: str) -> str:
        return '{"horizon_estimation": 0.4, "evidence_confidence": 0.8, "context_load": 0.3, "historical_success": 0.6}'


class NodeStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    DEPRECATED = "deprecated"

class NodeType(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    EXFILTRATION = "exfiltration"

class TaskDifficultyAssessment(BaseModel):
    horizon_estimation: float = Field(ge=0.0, le=1.0)
    evidence_confidence: float = Field(ge=0.0, le=1.0)
    context_load: float = Field(ge=0.0, le=1.0)
    historical_success: float = Field(ge=0.0, le=1.0)
    
    def calculate_score(self) -> float:
        """Calcula el Task Difficulty Index (TDI)."""
        w_H, w_E, w_C, w_S = 0.3, 0.3, 0.2, 0.2
        return (w_H * self.horizon_estimation) + \
               (w_E * (1.0 - self.evidence_confidence)) + \
               (w_C * self.context_load) + \
               (w_S * (1.0 - self.historical_success))

class AttackNode(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: str
    type: NodeType
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    hypothesis: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    status: NodeStatus = NodeStatus.PENDING
    tda_score: Optional[float] = None


class Planner:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "secretpassword")
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        self._initialize_db()

    def close(self):
        self.driver.close()

    def _initialize_db(self):
        """Asegura que existen las restricciones básicas."""
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:AttackNode) REQUIRE n.id IS UNIQUE")
            print("[Planner] Neo4j inicializado y restricción de ID creada.")

    def _sanitize_for_prompt(self, text: str) -> str:
        if not text: return ""
        return text.replace("```", "").replace('"', "'")

    def assess_task_difficulty(self, node: AttackNode) -> TaskDifficultyAssessment:
        safe_action = self._sanitize_for_prompt(node.action)
        safe_hypothesis = self._sanitize_for_prompt(node.hypothesis)
        
        prompt = f"""Ejerces el rol de Evaluador de Dificultad (TDA Evaluator).
Analiza la siguiente tarea propuesta para el grafo de ataque y emite un JSON estricto ponderando su viabilidad.

INFORMACIÓN DEL NODO:
- Tipo: {node.type.value}
- Acción (simbólica): {safe_action}
- Hipótesis (simbólica): {safe_hypothesis}
- Confianza actual de la evidencia: {node.confidence}

DEBES RETORNAR ÚNICA Y ESTRICTAMENTE UN JSON CON ESTA ESTRUCTURA EXACTA (valores float [0.0 - 1.0]):
{{
    "horizon_estimation": 0.5,
    "evidence_confidence": {node.confidence},
    "context_load": 0.4,
    "historical_success": 0.7
}}
No devuelvas texto libre, explicaciones ni etiquetas markdown. Solo JSON válido."""

        llm_response = call_llm_api(prompt)
        json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
        if not json_match:
            return TaskDifficultyAssessment(horizon_estimation=0.5, evidence_confidence=node.confidence, context_load=0.5, historical_success=0.5)
        
        try:
            tda_data = json.loads(json_match.group(0))
            return TaskDifficultyAssessment(**tda_data)
        except Exception:
            return TaskDifficultyAssessment(horizon_estimation=0.5, evidence_confidence=node.confidence, context_load=0.5, historical_success=0.5)

    def add_node(self, node: AttackNode, prerequisites: List[str] = None) -> bool:
        """Añade un nodo a Neo4j usando Cypher."""
        if node.tda_score is None:
            node.tda_score = self.assess_task_difficulty(node).calculate_score()

        node_data = node.model_dump()
        node_data['params'] = json.dumps(node_data['params'])
        node_data['evidence'] = json.dumps(node_data['evidence'])

        with self.driver.session() as session:
            session.execute_write(self._create_node_tx, node_data, prerequisites)
        return True

    @staticmethod
    def _create_node_tx(tx, node_data: dict, prerequisites: List[str]):
        query = """
        MERGE (n:AttackNode {id: $id})
        SET n.type = $type,
            n.action = $action,
            n.params = $params,
            n.evidence = $evidence,
            n.hypothesis = $hypothesis,
            n.confidence = $confidence,
            n.status = $status,
            n.tda_score = $tda_score
        """
        tx.run(query, **node_data)
        
        if prerequisites:
            for prereq_id in prerequisites:
                edge_query = """
                MATCH (p:AttackNode {id: $prereq_id})
                MATCH (n:AttackNode {id: $node_id})
                MERGE (p)-[:PREREQUISITE_FOR]->(n)
                """
                tx.run(edge_query, prereq_id=prereq_id, node_id=node_data['id'])

    def update_node(self, node_id: str, updates: Dict[str, Any]) -> bool:
        if 'params' in updates: updates['params'] = json.dumps(updates['params'])
        if 'evidence' in updates: updates['evidence'] = json.dumps(updates['evidence'])
        
        with self.driver.session() as session:
            query = "MATCH (n:AttackNode {id: $id}) SET n += $updates"
            session.run(query, id=node_id, updates=updates)
        return True

    def deprecate_node(self, node_id: str) -> bool:
        return self.update_node(node_id, {"status": NodeStatus.DEPRECATED})

    def extract_ready_actions(self) -> List[Dict[str, Any]]:
        """
        Extrae nodos 'pending' cuyas dependencias directas ya están 'completed'.
        Usa una consulta Cypher puramente relacional.
        """
        query = """
        MATCH (n:AttackNode {status: 'pending'})
        WHERE NOT (n)<-[:PREREQUISITE_FOR]-(:AttackNode {status: 'pending'})
          AND NOT (n)<-[:PREREQUISITE_FOR]-(:AttackNode {status: 'in_progress'})
          AND NOT (n)<-[:PREREQUISITE_FOR]-(:AttackNode {status: 'failed'})
        RETURN n.id as id, n.action as action, n.params as params
        """
        with self.driver.session() as session:
            result = session.run(query)
            ready = []
            for record in result:
                ready.append({
                    "id": record["id"],
                    "action": record["action"],
                    "params": json.loads(record["params"])
                })
            return ready

    def clear_graph(self):
        with self.driver.session() as session:
            session.run("MATCH (n:AttackNode) DETACH DELETE n")
