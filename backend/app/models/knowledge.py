import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from pgvector.sqlalchemy import Vector
from backend.app.database import Base


class KnowledgeEmbedding(Base):
    """
    Vector storage for MITRE ATT&CK techniques, SOC response playbooks,
    investigation guides, and cybersecurity domain knowledge.
    """
    __tablename__ = "knowledge_embeddings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    document_id = Column(String(64), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    source = Column(String(128), nullable=False)  # e.g., "MITRE ATT&CK Enterprise", "SOC Playbook"
    source_type = Column(String(64), index=True, nullable=False)  # "mitre_technique", "remediation_playbook", "investigation_guide"
    technique_id = Column(String(32), index=True, nullable=True)  # e.g., "T1110", "T1046"
    chunk_index = Column(Integer, default=0, nullable=False)
    content = Column(Text, nullable=False)
    embedding = Column(Vector(384), nullable=True)  # Standard 384 dimensions (all-MiniLM-L6-v2)
    metadata_json = Column(JSON, default=dict, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
