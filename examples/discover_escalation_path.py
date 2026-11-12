"""
Interactive Demonstration of IAM Privilege Escalation Pathfinding
Traces how an external contractor identity can escalate to Organization Administrator
and outputs Mermaid diagrams for security reporting.
"""
import os
import sys

repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

from iam_graph.graph_builder import CloudIAMGraphBuilder
from iam_graph.pathfinder import IAMPathfinder
from iam_graph.visualizer import GraphVisualizer


def main():
    print("=" * 80)
    print("      CLOUD IAM ATTACK PATH GRAPH: PRIVILEGE ESCALATION DISCOVERY        ")
    print("=" * 80)

    builder = CloudIAMGraphBuilder()
    graph = builder.build_enterprise_environment()
    pathfinder = IAMPathfinder(graph)

    source = "user_contractor_dev"
    target = "role_org_admin"

    print(f"[*] Analyzing Identity: {source}")
    print(f"[*] Target Asset      : {target}")

    path = pathfinder.find_shortest_attack_path(source, target)
    if not path:
        print("[-] No valid privilege escalation path found.")
        return

    print(f"\n[+] Critical Risk Identified! Shortest Attack Path ({path.hops} Hops, Cost: {path.total_cost}):")
    for i, (u, v, p) in enumerate(zip(path.nodes[:-1], path.nodes[1:], path.permissions), 1):
        print(f"    Step {i}: [{u}]  ====({p})====>  [{v}]")

    print("\n[*] Remediation Chokepoint Analysis:")
    chokepoints = pathfinder.compute_chokepoints(target, top_k=2)
    for rank, (node, score) in enumerate(chokepoints, 1):
        print(f"    #{rank} Severance Candidate: {node} (Centrality: {score:.4f})")
    print(f"    Action: Revoking permissions on '{chokepoints[0][0]}' severs the attack path completely.")

    print("\n[*] Mermaid Architecture Diagram:")
    print("-" * 50)
    print(GraphVisualizer.export_mermaid(path))
    print("-" * 50)
    print("=" * 80)


if __name__ == "__main__":
    main()
