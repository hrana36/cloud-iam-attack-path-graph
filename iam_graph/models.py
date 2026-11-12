"""
Cloud IAM Graph Data Models and Pathfinding Contracts
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional


class NodeType(str, Enum):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"
    INSTANCE_PROFILE = "INSTANCE_PROFILE"
    COMPUTE_INSTANCE = "COMPUTE_INSTANCE"
    STORAGE_BUCKET = "STORAGE_BUCKET"
    SECRET_STORE = "SECRET_STORE"


@dataclass
class IdentityNode:
    node_id: str
    name: str
    node_type: NodeType
    account_id: str = "123456789012"
    is_high_value_target: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RelationshipEdge:
    source_id: str
    target_id: str
    permission: str  # e.g. "sts:AssumeRole", "iam:PassRole", "s3:GetObject"
    cost: float = 1.0  # Exploitation cost weight
    mitre_technique: str = "T1078 - Valid Accounts"
    description: str = ""


@dataclass
class AttackPath:
    source_id: str
    target_id: str
    hops: int
    total_cost: float
    nodes: List[str]
    permissions: List[str]
    mitre_techniques: List[str]
    chokepoints: List[str] = field(default_factory=list)
