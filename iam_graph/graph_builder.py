"""
Graph Construction Engine for Multi-Cloud IAM Environments
"""
import random
from typing import Dict, Any, List, Optional
import networkx as nx
from iam_graph.models import IdentityNode, RelationshipEdge, NodeType


class CloudIAMGraphBuilder:
    """
    Constructs and populates directed graphs representing cloud identities,
    role-trust relationships, and cross-account privilege topologies.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes_registry: Dict[str, IdentityNode] = {}
        self.edges_registry: List[RelationshipEdge] = []

    def add_node(self, node: IdentityNode):
        self.nodes_registry[node.node_id] = node
        self.graph.add_node(
            node.node_id,
            name=node.name,
            node_type=node.node_type.value,
            account_id=node.account_id,
            is_high_value_target=node.is_high_value_target,
            **node.metadata,
        )

    def add_edge(self, edge: RelationshipEdge):
        self.edges_registry.append(edge)
        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            permission=edge.permission,
            weight=edge.cost,
            mitre_technique=edge.mitre_technique,
            description=edge.description,
        )

    def build_enterprise_environment(self, random_seed: int = 42) -> nx.DiGraph:
        """
        Synthesizes a realistic multi-cloud IAM graph containing standard business nodes
        and a hidden multi-hop privilege escalation path targeting the Organization Admin role.
        """
        random.seed(random_seed)

        # 1. High Value Targets (Crown Jewels)
        admin_role = IdentityNode(
            node_id="role_org_admin",
            name="OrganizationAdminRole",
            node_type=NodeType.ROLE,
            account_id="000111222333",
            is_high_value_target=True,
            metadata={"tier": "Tier-0", "permissions": "AdministratorAccess"},
        )
        vault_secret = IdentityNode(
            node_id="secret_prod_database",
            name="ProductionMasterSecret",
            node_type=NodeType.SECRET_STORE,
            account_id="000111222333",
            is_high_value_target=True,
            metadata={"tier": "Tier-0", "classification": "Critical"},
        )
        self.add_node(admin_role)
        self.add_node(vault_secret)

        # 2. Benign Departmental Nodes (40 identities)
        depts = ["finance", "marketing", "customer_support", "analytics"]
        for dept in depts:
            dept_group = IdentityNode(
                node_id=f"group_{dept}",
                name=f"{dept.capitalize()}Group",
                node_type=NodeType.GROUP,
            )
            self.add_node(dept_group)

            dept_role = IdentityNode(
                node_id=f"role_{dept}_readonly",
                name=f"{dept.capitalize()}ReadOnlyRole",
                node_type=NodeType.ROLE,
            )
            self.add_node(dept_role)
            self.add_edge(RelationshipEdge(
                source_id=f"group_{dept}",
                target_id=f"role_{dept}_readonly",
                permission="sts:AssumeRole",
                cost=1.0,
            ))

            for i in range(1, 6):
                u_id = f"user_{dept}_{i}"
                user_node = IdentityNode(
                    node_id=u_id,
                    name=f"{dept.capitalize()}User{i}",
                    node_type=NodeType.USER,
                )
                self.add_node(user_node)
                self.add_edge(RelationshipEdge(
                    source_id=u_id,
                    target_id=f"group_{dept}",
                    permission="iam:AddToGroup",
                    cost=1.0,
                ))

        # 3. Intermediate Infrastructure Nodes
        infra_nodes = [
            IdentityNode("user_contractor_dev", "ContractorDeveloper", NodeType.USER, metadata={"role": "External"}),
            IdentityNode("role_dev_lambda", "DevLambdaExecutionRole", NodeType.ROLE),
            IdentityNode("bucket_staging_deployments", "StagingDeploymentsBucket", NodeType.STORAGE_BUCKET),
            IdentityNode("profile_ec2_cicd_runner", "CICDRunnerInstanceProfile", NodeType.INSTANCE_PROFILE),
            IdentityNode("role_cluster_operator", "KubernetesClusterOperatorRole", NodeType.ROLE),
        ]
        for node in infra_nodes:
            self.add_node(node)

        # 4. Inject Multi-Hop Privilege Escalation Attack Chain:
        # Hop 1: Contractor User -> AssumeRole -> DevLambdaExecutionRole (cost=1.0)
        self.add_edge(RelationshipEdge(
            source_id="user_contractor_dev",
            target_id="role_dev_lambda",
            permission="sts:AssumeRole",
            cost=1.0,
            mitre_technique="T1078 - Valid Accounts",
            description="Contractor credentials allow assuming dev serverless execution role",
        ))

        # Hop 2: DevLambdaExecutionRole -> s3:GetObject -> StagingDeploymentsBucket (cost=1.5)
        self.add_edge(RelationshipEdge(
            source_id="role_dev_lambda",
            target_id="bucket_staging_deployments",
            permission="s3:GetObject",
            cost=1.5,
            mitre_technique="T1530 - Data from Cloud Storage",
            description="Dev role possesses unconstrained read access to staging deployment archives",
        ))

        # Hop 3: StagingDeploymentsBucket -> Extract SSH / Instance Credentials -> CICDRunnerInstanceProfile (cost=2.0)
        self.add_edge(RelationshipEdge(
            source_id="bucket_staging_deployments",
            target_id="profile_ec2_cicd_runner",
            permission="ec2:AssociateIamInstanceProfile",
            cost=2.0,
            mitre_technique="T1078.004 - Cloud Accounts",
            description="Leaked configuration keys allow attaching instance profile to arbitrary instances",
        ))

        # Hop 4: CICDRunnerInstanceProfile -> iam:PassRole -> KubernetesClusterOperatorRole (cost=1.5)
        self.add_edge(RelationshipEdge(
            source_id="profile_ec2_cicd_runner",
            target_id="role_cluster_operator",
            permission="iam:PassRole",
            cost=1.5,
            mitre_technique="T1098 - Account Manipulation",
            description="CI/CD runner profile can pass cluster operator role to spawned pods",
        ))

        # Hop 5: KubernetesClusterOperatorRole -> iam:AttachRolePolicy -> OrganizationAdminRole (Crown Jewel!) (cost=1.0)
        self.add_edge(RelationshipEdge(
            source_id="role_cluster_operator",
            target_id="role_org_admin",
            permission="iam:AttachRolePolicy",
            cost=1.0,
            mitre_technique="T1098.001 - Additional Cloud Credentials",
            description="Cluster operator possesses permission to attach full AdministratorAccess policy",
        ))

        # Branch from Org Admin to Production Database Secret
        self.add_edge(RelationshipEdge(
            source_id="role_org_admin",
            target_id="secret_prod_database",
            permission="secretsmanager:GetSecretValue",
            cost=0.5,
            mitre_technique="T1552 - Unsecured Credentials",
        ))

        return self.graph
