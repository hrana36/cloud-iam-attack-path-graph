"""
Unit & Integration Test Suite for Cloud IAM Attack Path Graph
"""
import os
import sys

repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

import pytest
import networkx as nx
from iam_graph.models import IdentityNode, RelationshipEdge, NodeType
from iam_graph.graph_builder import CloudIAMGraphBuilder
from iam_graph.pathfinder import IAMPathfinder
from iam_graph.visualizer import GraphVisualizer


@pytest.fixture
def enterprise_graph():
    builder = CloudIAMGraphBuilder()
    return builder.build_enterprise_environment(random_seed=42)


def test_graph_builder_node_attributes(enterprise_graph):
    assert enterprise_graph.number_of_nodes() > 20
    assert enterprise_graph.number_of_edges() > 20
    assert enterprise_graph.has_node("role_org_admin")
    assert enterprise_graph.nodes["role_org_admin"]["is_high_value_target"] is True


def test_shortest_path_discovery(enterprise_graph):
    pathfinder = IAMPathfinder(enterprise_graph)
    path = pathfinder.find_shortest_attack_path("user_contractor_dev", "role_org_admin")

    assert path is not None
    assert path.source_id == "user_contractor_dev"
    assert path.target_id == "role_org_admin"
    assert path.hops == 5
    assert "sts:AssumeRole" in path.permissions
    assert "iam:PassRole" in path.permissions
    assert "iam:AttachRolePolicy" in path.permissions


def test_unreachable_node_returns_none(enterprise_graph):
    # Add an isolated node with no incoming/outgoing edges
    builder = CloudIAMGraphBuilder()
    g = builder.build_enterprise_environment()
    g.add_node("isolated_guest", is_high_value_target=False)

    pathfinder = IAMPathfinder(g)
    path = pathfinder.find_shortest_attack_path("isolated_guest", "role_org_admin")
    assert path is None


def test_blast_radius(enterprise_graph):
    pathfinder = IAMPathfinder(enterprise_graph)
    blast = pathfinder.compute_blast_radius("user_contractor_dev")

    assert blast["total_reachable_nodes"] >= 5
    assert blast["max_propagation_depth"] >= 5
    assert "role_org_admin" in blast["high_value_targets_at_risk"]


def test_chokepoints(enterprise_graph):
    pathfinder = IAMPathfinder(enterprise_graph)
    chokepoints = pathfinder.compute_chokepoints("role_org_admin", top_k=3)

    assert len(chokepoints) > 0
    top_node, score = chokepoints[0]
    assert score > 0.0
    # Top chokepoints must be an intermediate node on the chain
    assert top_node in ["role_cluster_operator", "profile_ec2_cicd_runner", "bucket_staging_deployments", "role_dev_lambda"]


def test_mermaid_export(enterprise_graph):
    pathfinder = IAMPathfinder(enterprise_graph)
    path = pathfinder.find_shortest_attack_path("user_contractor_dev", "role_org_admin")
    mermaid = GraphVisualizer.export_mermaid(path)

    assert "flowchart LR" in mermaid
    assert "user_contractor_dev" in mermaid
    assert "role_org_admin" in mermaid
    assert "iam:PassRole" in mermaid
