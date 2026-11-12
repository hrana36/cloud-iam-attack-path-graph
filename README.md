# Cloud-IAM-Attack-Path-Graph

[![Cloud IAM Attack Path CI](https://github.com/hrana36/cloud-iam-attack-path-graph/actions/workflows/ci.yml/badge.svg)](https://github.com/hrana36/cloud-iam-attack-path-graph/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Cloud Security](https://img.shields.io/badge/MITRE%20ATT%26CK-T1078%20%7C%20T1098%20%7C%20T1530-orange.svg)](https://attack.mitre.org/)

An automated graph-theoretic analysis engine for discovering multi-hop privilege escalation trajectories, lateral movement vectors, and architectural chokepoints across complex multi-cloud IAM environments (AWS, Azure, GCP).

---

## 1. Abstract & Threat Model

In modern multi-account enterprise clouds, privilege escalation rarely stems from a single blatantly misconfigured policy. Instead, adversaries exploit **toxic permission combinations** and indirect trust relationships—chaining together seemingly low-risk permissions across disparate resources (e.g., assuming a developer role, accessing deployment S3 buckets, retrieving temporary instance credentials, and passing roles to achieve root organization compromise).

`cloud-iam-attack-path-graph` models multi-cloud IAM relationships as a directed attributed multigraph. Using graph algorithms (weighted Dijkstra traversal, blast radius computation, and betweenness centrality chokepoint analysis), the engine discovers the shortest, least-cost privilege escalation chains to High-Value Targets (HVTs) in sub-millisecond execution times.

```mermaid
flowchart LR
    U["Contractor User"] -->|"sts:AssumeRole"| R1["Dev Lambda Role"]
    R1 -->|"s3:GetObject"| B["Staging Deployments Bucket"]
    B -->|"ec2:AssociateInstanceProfile"| P["CI/CD Runner Profile"]
    P -->|"iam:PassRole"| R2["Cluster Operator Role"]
    R2 -->|"iam:AttachRolePolicy"| HVT["Organization Admin (Crown Jewel)"]
```

---

## 2. Graph Formulation & Algorithmic Foundations

### 2.1 Attributed Graph Topology
The cloud infrastructure is modeled as a directed graph $G = (V, E)$ where:
- **Vertices $V$**: Represent identity principals, roles, service accounts, compute instances, storage buckets, and secret managers:
  $$V = V_{user} \cup V_{role} \cup V_{profile} \cup V_{resource} \cup V_{secret}$$
- **Edges $E$**: Directed transitions $(u, v) \in E$ representing granular cloud permissions (`sts:AssumeRole`, `iam:PassRole`, `s3:GetObject`) with an associated exploitation cost weight $w(u, v) \ge 0$.

### 2.2 Shortest Privilege Escalation Path
Finding the minimum-cost exploit trajectory from compromised identity $s$ to crown jewel target $t$ is formulated as:

$$\min_{P \in \mathcal{P}_{s \to t}} \sum_{e \in P} w(e)$$

where $\mathcal{P}_{s \to t}$ is the set of all valid directed permission chains connecting $s$ to $t$. Dijkstra's algorithm solves this in $\mathcal{O}(|E| + |V| \log |V|)$ time.

### 2.3 Architectural Chokepoints (Betweenness Centrality)
To identify intermediate identities whose remediation maximally severs escalation paths, the engine computes betweenness centrality on the subgraph of ancestor identities reaching target $t$:

$$C_B(v) = \sum_{s \ne v \ne t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$

where $\sigma_{st}$ is the total number of shortest attack paths from $s$ to $t$, and $\sigma_{st}(v)$ is the number of those paths passing through intermediate node $v$.

---

## 3. Empirical Benchmark Results

Evaluated on an enterprise topology containing 35 identity nodes, 30 permission edges, and injected multi-hop privilege escalation chains targeting organizational root administration.

| Analysis Metric | Measured Value | Evaluation Outcome |
| :--- | :---: | :---: |
| **Shortest Exploit Trajectory** | **5 hops** | Contractor $\to$ DevRole $\to$ S3Bucket $\to$ Runner $\to$ ClusterOp $\to$ **OrgAdmin** |
| **Cumulative Path Cost** | **7.0** | Weighted exploitation difficulty |
| **Pathfinding Traversal Latency** | **499.80 $\mu\text{s}$** | **Sub-millisecond real-time graph search** |
| **Total Reachable Blast Radius** | 6 nodes | 2 High-Value Targets at risk (`role_org_admin`, `secret_prod_database`) |
| **Blast Radius Compute Latency** | **381.10 $\mu\text{s}$** | Sub-millisecond impact scoping |
| **Primary Architectural Chokepoint** | `bucket_staging_deployments` | **Remediating cuts 100% of attack paths** |

Graph topology plots and full metrics are exported in [`benchmarks/iam_attack_graph_topology.png`](benchmarks/iam_attack_graph_topology.png) and [`benchmarks/attack_graph_metrics.json`](benchmarks/attack_graph_metrics.json).

---

## 4. Repository Structure

```
cloud-iam-attack-path-graph/
├── .github/workflows/
│   └── ci.yml                          # GitHub Actions Multi-Python CI (3.10 - 3.12)
├── iam_graph/
│   ├── __init__.py                     # Module exports
│   ├── models.py                       # IdentityNode, RelationshipEdge, AttackPath dataclasses
│   ├── graph_builder.py                # NetworkX directed graph builder & enterprise environment
│   ├── pathfinder.py                   # Dijkstra shortest paths, blast radius, chokepoints
│   └── visualizer.py                   # Topology rendering with Matplotlib & Mermaid export
├── benchmarks/
│   ├── run_pathfinding_benchmark.py    # Empirical pathfinding benchmark runner
│   ├── attack_graph_metrics.json       # Structured benchmark results
│   └── iam_attack_graph_topology.png   # High-resolution topology visualization plot
├── examples/
│   └── discover_escalation_path.py     # Interactive CLI demonstration
├── tests/
│   └── test_iam_graph.py               # Complete Pytest test suite (100% pass)
├── requirements.txt
├── pyproject.toml
├── LICENSE                             # MIT License
└── README.md
```

---

## 5. Quickstart & Verification

### Installation
```bash
git clone https://github.com/hrana36/cloud-iam-attack-path-graph.git
cd cloud-iam-attack-path-graph
pip install -r requirements.txt
```

### Run Test Suite
```bash
python -m pytest tests -v
```

### Run Empirical Benchmark
```bash
python benchmarks/run_pathfinding_benchmark.py
```

### Run Interactive Pathfinding Demo
```bash
python examples/discover_escalation_path.py
```

---

## 6. Academic References & Citations

```bibtex
@inproceedings{dijkstra1959note,
  title={A Note on Two Problems in Connexion with Graphs},
  author={Dijkstra, Edsger W.},
  journal={Numerische Mathematik},
  volume={1},
  number={1},
  pages={269--271},
  year={1959}
}

@inproceedings{freeman1977set,
  title={A Set of Measures of Centrality Based on Betweenness},
  author={Freeman, Linton C.},
  journal={Sociometry},
  pages={35--41},
  year={1977}
}

@inproceedings{sheyner2002automated,
  title={Automated Generation and Analysis of Attack Graphs},
  author={Sheyner, Oleg and Haines, Joshua and Jha, Somesh and Lippmann, Richard and Wing, Jeannette M.},
  booktitle={IEEE Symposium on Security and Privacy (S\&P)},
  pages={273--284},
  year={2002}
}
```

---

## 7. License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
