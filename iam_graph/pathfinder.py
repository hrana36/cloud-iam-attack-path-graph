"""
Graph-Theoretic Pathfinding and Chokepoint Identification Engine
"""
from typing import List, Dict, Any, Optional, Tuple, Set
import networkx as nx
from iam_graph.models import AttackPath


class IAMPathfinder:
    """
    Computes shortest privilege escalation chains, blast radii, and architectural chokepoints.
    """

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def find_shortest_attack_path(self, source_id: str, target_id: str) -> Optional[AttackPath]:
        """
        Calculates the minimum-cost privilege escalation path between source and target identities
        using Dijkstra's shortest path algorithm.
        """
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            return None

        try:
            node_path = nx.dijkstra_path(self.graph, source_id, target_id, weight="weight")
            total_cost = nx.dijkstra_path_length(self.graph, source_id, target_id, weight="weight")
        except nx.NetworkXNoPath:
            return None

        hops = len(node_path) - 1
        permissions = []
        mitre_techs = []

        for u, v in zip(node_path[:-1], node_path[1:]):
            edge_data = self.graph.get_edge_data(u, v)
            permissions.append(edge_data.get("permission", "unknown"))
            mitre_techs.append(edge_data.get("mitre_technique", "T1078"))

        return AttackPath(
            source_id=source_id,
            target_id=target_id,
            hops=hops,
            total_cost=round(float(total_cost), 2),
            nodes=node_path,
            permissions=permissions,
            mitre_techniques=list(dict.fromkeys(mitre_techs)),
        )

    def find_all_reachable_targets(self, source_id: str) -> List[AttackPath]:
        """
        Discovers all High-Value Targets (HVTs) reachable from the initial identity,
        ordered by lowest cumulative exploitation cost.
        """
        if not self.graph.has_node(source_id):
            return []

        hvt_nodes = [
            n for n, attr in self.graph.nodes(data=True)
            if attr.get("is_high_value_target", False)
        ]

        paths = []
        for target in hvt_nodes:
            path = self.find_shortest_attack_path(source_id, target)
            if path:
                paths.append(path)

        paths.sort(key=lambda p: p.total_cost)
        return paths

    def compute_chokepoints(self, target_id: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """
        Identifies structural chokepoint nodes using path betweenness centrality.
        Remediating a top chokepoint maximally severs inbound escalation trajectories.
        """
        if not self.graph.has_node(target_id):
            return []

        # Find all ancestor nodes that can reach target_id
        ancestors: Set[str] = nx.ancestors(self.graph, target_id)
        if not ancestors:
            return []

        subgraph_nodes = ancestors | {target_id}
        subgraph = self.graph.subgraph(subgraph_nodes)

        centrality = nx.betweenness_centrality(subgraph, weight="weight")
        # Exclude the target itself from chokepoint candidates
        centrality.pop(target_id, None)

        ranked = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_k]

    def compute_blast_radius(self, source_id: str) -> Dict[str, Any]:
        """
        Computes the complete blast radius of a compromised identity node.
        """
        if not self.graph.has_node(source_id):
            return {"reachable_identities": 0, "max_depth": 0, "high_value_targets_at_risk": []}

        descendants = nx.descendants(self.graph, source_id)
        lengths = nx.single_source_shortest_path_length(self.graph, source_id)

        hvts = [
            n for n in descendants
            if self.graph.nodes[n].get("is_high_value_target", False)
        ]

        max_depth = max(lengths.values()) if lengths else 0

        return {
            "source_identity": source_id,
            "total_reachable_nodes": len(descendants),
            "max_propagation_depth": max_depth,
            "high_value_targets_at_risk": hvts,
        }
