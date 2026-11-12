"""
Graph Visualization and Topology Rendering Engine
"""
from typing import Optional
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from iam_graph.models import AttackPath


class GraphVisualizer:
    """
    Renders attack paths and cloud identity graphs into publication plots and Mermaid diagrams.
    """

    @classmethod
    def export_mermaid(cls, path: AttackPath) -> str:
        """Generates Mermaid flowchart representation of an attack path."""
        lines = ["flowchart LR"]
        for u, v, perm in zip(path.nodes[:-1], path.nodes[1:], path.permissions):
            clean_u = u.replace("-", "_")
            clean_v = v.replace("-", "_")
            lines.append(f'    {clean_u}["{u}"] -->|"{perm}"| {clean_v}["{v}"]')
        return "\n".join(lines)

    @classmethod
    def render_attack_graph_plot(
        cls,
        graph: nx.DiGraph,
        path: Optional[AttackPath],
        output_path: str,
        title: str = "Multi-Cloud IAM Attack Path Graph",
    ):
        """
        Renders topological graph highlighting the shortest privilege escalation path.
        """
        plt.figure(figsize=(12, 8), dpi=300)
        pos = nx.spring_layout(graph, seed=42, k=0.45)

        # Draw all background nodes
        all_nodes = list(graph.nodes())
        hvt_nodes = [n for n, d in graph.nodes(data=True) if d.get("is_high_value_target", False)]
        path_nodes = path.nodes if path else []
        regular_nodes = [n for n in all_nodes if n not in hvt_nodes and n not in path_nodes]

        # Background nodes
        nx.draw_networkx_nodes(graph, pos, nodelist=regular_nodes, node_color="#aec7e8", node_size=350, alpha=0.6)
        # High value targets (Crown jewels - Gold)
        nx.draw_networkx_nodes(graph, pos, nodelist=hvt_nodes, node_color="#d62728", node_size=700, edgecolors="black", linewidths=2.0)
        # Path nodes (Escalation chain - Orange/Red)
        if path_nodes:
            nx.draw_networkx_nodes(graph, pos, nodelist=path_nodes, node_color="#ff7f0e", node_size=550, edgecolors="darkred", linewidths=1.8)

        # Background edges
        all_edges = list(graph.edges())
        path_edges = list(zip(path.nodes[:-1], path.nodes[1:])) if path else []
        bg_edges = [e for e in all_edges if e not in path_edges]

        nx.draw_networkx_edges(graph, pos, edgelist=bg_edges, edge_color="#c7c7c7", width=1.0, alpha=0.5, arrows=True, arrowsize=10)
        if path_edges:
            nx.draw_networkx_edges(graph, pos, edgelist=path_edges, edge_color="#d62728", width=3.0, arrows=True, arrowsize=18)

        # Labels for path nodes and HVTs
        labels = {n: n for n in set(path_nodes) | set(hvt_nodes)}
        nx.draw_networkx_labels(graph, pos, labels=labels, font_size=8, font_weight="bold")

        plt.title(title, fontsize=14, fontweight="bold")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
