"""Kubernetes security scanner for VulnBuster.

This module provides functionality to scan Kubernetes clusters for security issues,
including misconfigurations, vulnerabilities, and compliance with best practices.
"""
"""Kubernetes security scanner for VulnBuster.

This module provides functionality to scan Kubernetes clusters for security issues,
including misconfigurations, vulnerabilities, and compliance with best practices.
"""
import logging
import re
import json
import yaml
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from kubernetes import client, config, dynamic
from kubernetes.config.config_exception import ConfigException
from kubernetes.client import api_client
from kubernetes.client.exceptions import ApiException

from ..models import AWSFinding, AWSSeverity, AWSService

logger = logging.getLogger(__name__)

class KubernetesScanner:
    """Scanner for Kubernetes security assessment."""
    
    def __init__(self, kubeconfig: str = None, context: str = None):
        """Initialize the Kubernetes scanner.
        
        Args:
            kubeconfig: Path to kubeconfig file (default: ~/.kube/config)
            context: Name of the kubeconfig context to use
        """
        self.kubeconfig = kubeconfig
        self.context = context
        self.api_client = None
        self.core_v1 = None
        self.apps_v1 = None
        self.networking_v1 = None
        self.rbac_auth_v1 = None
        self.policy_v1 = None
        self._init_kubernetes_client()
    
    def _init_kubernetes_client(self):
        """Initialize the Kubernetes client."""
        try:
            if self.kubeconfig:
                config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            else:
                # Try to load in-cluster config first, fall back to kubeconfig
                try:
                    config.load_incluster_config()
                except ConfigException:
                    config.load_kube_config(context=self.context)
            
            # Initialize API clients
            self.api_client = client.ApiClient()
            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            self.rbac_auth_v1 = client.RbacAuthorizationV1Api()
            self.policy_v1 = client.PolicyV1Api()
            
            logger.info("Successfully initialized Kubernetes client")
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {str(e)}")
            raise
    
    async def scan_cluster(self, run_cis_checks: bool = True) -> List[AWSFinding]:
        """Perform a comprehensive security scan of the Kubernetes cluster.
        
        Args:
            run_cis_checks: Whether to run CIS benchmark checks
            
        Returns:
            List of security findings
        """
        if not self.api_client:
            raise RuntimeError("Kubernetes client not initialized")
        
        findings = []
        
        # Run all security checks
        findings.extend(await self.check_rbac_issues())
        findings.extend(await self.check_pod_security())
        findings.extend(await self.check_network_policies())
        findings.extend(await self.check_secrets_management())
        findings.extend(await self.check_workload_security())
        findings.extend(await self.check_cluster_security())
        
        # Run CIS benchmark checks if enabled
        if run_cis_checks:
            findings.extend(await self.run_cis_benchmark_checks())
        
        return findings
    
    async def check_rbac_issues(self) -> List[AWSFinding]:
        """Check for RBAC misconfigurations.
        
        Returns:
            List of RBAC-related findings
        """
        findings = []
        
        try:
            # Check for cluster-admin bindings
            cluster_roles = self.rbac_auth_v1.list_cluster_role_binding().items
            for role_binding in cluster_roles:
                if role_binding.role_ref.name == 'cluster-admin':
                    for subject in role_binding.subjects:
                        if subject.kind == 'ServiceAccount':
                            findings.append(AWSFinding(
                                service=AWSService.EKS,
                                resource_id=f"{subject.namespace}/{subject.name}",
                                finding_type="CLUSTER_ADMIN_SERVICE_ACCOUNT",
                                severity=AWSSeverity.HIGH,
                                description=f"ServiceAccount {subject.name} in namespace {subject.namespace} has cluster-admin privileges",
                                details={
                                    "role_binding": role_binding.metadata.name,
                                    "subject": f"{subject.kind}: {subject.name}",
                                    "namespace": subject.namespace
                                },
                                remediation=(
                                    "Avoid using cluster-admin privileges for service accounts. "
                                    "Follow the principle of least privilege and create specific roles with only the necessary permissions."
                                ),
                                references=[
                                    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles"
                                ]
                            ))
            
            # Check for wildcard permissions
            cluster_roles = self.rbac_auth_v1.list_cluster_role().items
            for role in cluster_roles:
                for rule in role.rules:
                    if '*' in rule.verbs or '*' in rule.resources:
                        findings.append(AWSFinding(
                            service=AWSService.EKS,
                            resource_id=role.metadata.name,
                            finding_type="WILDCARD_PERMISSIONS",
                            severity=AWSSeverity.HIGH,
                            description=f"ClusterRole {role.metadata.name} contains wildcard permissions",
                            details={
                                "api_groups": rule.api_groups,
                                "resources": rule.resources,
                                "verbs": rule.verbs
                            },
                            remediation=(
                                "Avoid using wildcard permissions in ClusterRoles. "
                                "Define specific resources and verbs to follow the principle of least privilege."
                            ),
                            references=[
                                "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"
                            ]
                        ))
        except Exception as e:
            logger.error(f"Error checking RBAC issues: {str(e)}")
        
        return findings
    
    async def check_pod_security(self) -> List[AWSFinding]:
        """Check for pod security issues.
        
        Returns:
            List of pod security findings
        """
        findings = []
        
        try:
            # Check for privileged containers
            pods = self.core_v1.list_pod_for_all_namespaces().items
            for pod in pods:
                for container in pod.spec.containers:
                    security_context = container.security_context
                    if security_context and security_context.privileged:
                        findings.append(AWSFinding(
                            service=AWSService.EKS,
                            resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}/{container.name}",
                            finding_type="PRIVILEGED_CONTAINER",
                            severity=AWSSeverity.HIGH,
                            description=f"Container {container.name} in pod {pod.metadata.name} is running in privileged mode",
                            details={
                                "namespace": pod.metadata.namespace,
                                "pod": pod.metadata.name,
                                "container": container.name
                            },
                            remediation=(
                                "Avoid running containers in privileged mode. "
                                "If elevated privileges are needed, use specific capabilities instead."
                            ),
                            references=[
                                "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
                            ]
                        ))
                
                # Check host namespaces
                if pod.spec.host_network or pod.spec.host_pid or pod.spec.host_ipc:
                    findings.append(AWSFinding(
                        service=AWSService.EKS,
                        resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                        finding_type="HOST_NAMESPACE_SHARING",
                        severity=AWSSeverity.HIGH,
                        description=f"Pod {pod.metadata.name} is sharing host namespaces",
                        details={
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "host_network": pod.spec.host_network,
                            "host_pid": pod.spec.host_pid,
                            "host_ipc": pod.spec.host_ipc
                        },
                        remediation=(
                            "Avoid sharing host namespaces with pods. "
                            "This can be a security risk as it allows potential access to host resources."
                        ),
                        references=[
                            "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
                        ]
                    ))
        except Exception as e:
            logger.error(f"Error checking pod security: {str(e)}")
        
        return findings
    
    async def check_network_policies(self) -> List[AWSFinding]:
        """Check for network policy issues.
        
        Returns:
            List of network policy findings
        """
        findings = []
        
        try:
            # Check if network policies are in use
            namespaces = self.core_v1.list_namespace().items
            for ns in namespaces:
                try:
                    network_policies = self.networking_v1.list_namespaced_network_policy(ns.metadata.name).items
                    if not network_policies:
                        findings.append(AWSFinding(
                            service=AWSService.EKS,
                            resource_id=ns.metadata.name,
                            finding_type="MISSING_NETWORK_POLICY",
                            severity=AWSSeverity.MEDIUM,
                            description=f"Namespace {ns.metadata.name} has no network policies defined",
                            details={
                                "namespace": ns.metadata.name
                            },
                            remediation=(
                                "Define NetworkPolicies to restrict traffic between pods. "
                                "This follows the principle of least privilege for network communication."
                            ),
                            references=[
                                "https://kubernetes.io/docs/concepts/services-networking/network-policies/"
                            ]
                        ))
                except Exception as e:
                    logger.warning(f"Error checking network policies for namespace {ns.metadata.name}: {str(e)}")
        except Exception as e:
            logger.error(f"Error checking network policies: {str(e)}")
        
        return findings
    
    async def check_secrets_management(self) -> List[AWSFinding]:
        """Check for secrets management issues.
        
        Returns:
            List of secrets management findings
        """
        findings = []
        
        try:
            # Check for secrets in environment variables
            pods = self.core_v1.list_pod_for_all_namespaces().items
            for pod in pods:
                for container in pod.spec.containers:
                    if container.env:
                        for env in container.env:
                            if env.value_from and env.value_from.secret_key_ref:
                                findings.append(AWSFinding(
                                    service=AWSService.EKS,
                                    resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}/{container.name}",
                                    finding_type="SECRET_IN_ENV",
                                    severity=AWSSeverity.MEDIUM,
                                    description=f"Container {container.name} in pod {pod.metadata.name} uses secrets in environment variables",
                                    details={
                                        "namespace": pod.metadata.namespace,
                                        "pod": pod.metadata.name,
                                        "container": container.name,
                                        "secret": env.value_from.secret_key_ref.name,
                                        "key": env.value_from.secret_key_ref.key
                                    },
                                    remediation=(
                                        "Avoid using secrets in environment variables. "
                                        "Use volume mounts for secrets to prevent accidental exposure."
                                    ),
                                    references=[
                                        "https://kubernetes.io/docs/concepts/configuration/secret/#best-practices"
                                    ]
                                ))
        except Exception as e:
            logger.error(f"Error checking secrets management: {str(e)}")
        
        return findings
    
    async def check_workload_security(self) -> List[AWSFinding]:
        """Check for workload security issues.
        
        Returns:
            List of workload security findings
        """
        findings = []
        
        try:
            # Check for resources without resource limits
            deployments = self.apps_v1.list_deployment_for_all_namespaces().items
            for deployment in deployments:
                for container in deployment.spec.template.spec.containers:
                    if not container.resources or not container.resources.limits:
                        findings.append(AWSFinding(
                            service=AWSService.EKS,
                            resource_id=f"{deployment.metadata.namespace}/{deployment.metadata.name}/{container.name}",
                            finding_type="MISSING_RESOURCE_LIMITS",
                            severity=AWSSeverity.MEDIUM,
                            description=f"Container {container.name} in deployment {deployment.metadata.name} has no resource limits defined",
                            details={
                                "namespace": deployment.metadata.namespace,
                                "deployment": deployment.metadata.name,
                                "container": container.name
                            },
                            remediation=(
                                "Define resource limits for all containers to prevent resource exhaustion. "
                                "This helps ensure cluster stability and fair resource allocation."
                            ),
                            references=[
                                "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
                            ]
                        ))
        except Exception as e:
            logger.error(f"Error checking workload security: {str(e)}")
        
        return findings
    
    async def check_cluster_security(self) -> List[AWSFinding]:
        """Check for cluster-level security issues.
        
        Returns:
            List of cluster security findings
        """
        findings = []
        
        try:
            # Check for default service accounts with tokens
            service_accounts = self.core_v1.list_service_account_for_all_namespaces().items
            for sa in service_accounts:
                if sa.metadata.name == 'default' and sa.automount_service_account_token is not False:
                    findings.append(AWSFinding(
                        service=AWSService.EKS,
                        resource_id=f"{sa.metadata.namespace}/{sa.metadata.name}",
                        finding_type="DEFAULT_SERVICE_ACCOUNT_TOKEN",
                        severity=AWSSeverity.MEDIUM,
                        description=f"Default service account in namespace {sa.metadata.namespace} has token auto-mounting enabled",
                        details={
                            "namespace": sa.metadata.namespace,
                            "service_account": sa.metadata.name
                        },
                        remediation=(
                            "Disable auto-mounting of service account tokens for default service accounts. "
                            "Create dedicated service accounts with least privilege for your applications."
                        ),
                        references=[
                            "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"
                        ]
                    ))
            
            # Check for anonymous authentication
            try:
                api_server_config = self.core_v1.read_namespaced_config_map(
                    name="extension-apiserver-authentication",
                    namespace="kube-system"
                )
                
                if api_server_config.data.get("requestheader-username-headers", "").lower() == "x-remote-user":
                    findings.append(AWSFinding(
                        service=AWSService.EKS,
                        resource_id="kube-apiserver",
                        finding_type="ANONYMOUS_AUTH_ENABLED",
                        severity=AWSSeverity.HIGH,
                        description="Anonymous authentication is enabled in the API server",
                        details={
                            "config_map": "extension-apiserver-authentication",
                            "namespace": "kube-system"
                        },
                        remediation=(
                            "Disable anonymous authentication in the API server. "
                            "This prevents unauthenticated requests to the Kubernetes API."
                        ),
                        references=[
                            "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests"
                        ]
                    ))
            except ApiException as e:
                if e.status != 403:  # Ignore forbidden errors (common in managed clusters)
                    logger.warning(f"Error checking API server config: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error checking cluster security: {str(e)}")
        
        return findings
        
    async def run_cis_benchmark_checks(self) -> List[AWSFinding]:
        """Run CIS Kubernetes Benchmark checks.
        
        Returns:
            List of CIS benchmark findings
        """
        findings = []
        
        try:
            # 1. Control Plane Components
            findings.extend(await self._check_control_plane_components())
            
            # 2. etcd
            findings.extend(await self._check_etcd_configuration())
            
            # 3. Control Plane Configuration
            findings.extend(await self._check_control_plane_config())
            
            # 4. Worker Nodes
            findings.extend(await self._check_worker_nodes())
            
            # 5. Policies
            findings.extend(await self._check_policies())
            
        except Exception as e:
            logger.error(f"Error running CIS benchmark checks: {str(e)}")
            
        return findings
    
    async def _check_control_plane_components(self) -> List[AWSFinding]:
        """Check control plane components against CIS benchmarks."""
        findings = []
        
        try:
            # Check if API server is configured with --anonymous-auth=false
            api_server_pods = self.core_v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            ).items
            
            for pod in api_server_pods:
                for container in pod.spec.containers:
                    if "kube-apiserver" in container.command:
                        if "--anonymous-auth=true" in container.command or "--anonymous-auth" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.2.1",
                                title="Ensure that the --anonymous-auth argument is set to false",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
                        
                        # Check for --authorization-mode=Node,RBAC
                        if "--authorization-mode=Node,RBAC" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.2.7",
                                title="Ensure that the --authorization-mode argument includes Node and RBAC",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
                        
                        # Check for --audit-log-path and --audit-log-maxage
                        if "--audit-log-path" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.2.18",
                                title="Ensure that the --audit-log-path argument is set as appropriate",
                                severity=AWSSeverity.MEDIUM,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
                        
                        if "--audit-log-maxage" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.2.20",
                                title="Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
                                severity=AWSSeverity.MEDIUM,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
            
            # Check controller manager
            controller_manager_pods = self.core_v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-controller-manager"
            ).items
            
            for pod in controller_manager_pods:
                for container in pod.spec.containers:
                    if "kube-controller-manager" in container.command:
                        # Check for --use-service-account-credentials=true
                        if "--use-service-account-credentials=true" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.3.1",
                                title="Ensure that the --use-service-account-credentials argument is set to true",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
                        
                        # Check for --feature-gates=RotateKubeletServerCertificate=true
                        if "--feature-gates=RotateKubeletServerCertificate=true" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.3.2",
                                title="Ensure that the --use-service-account-credentials argument is set to true",
                                severity=AWSSeverity.MEDIUM,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
            
            # Check scheduler
            scheduler_pods = self.core_v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-scheduler"
            ).items
            
            for pod in scheduler_pods:
                for container in pod.spec.containers:
                    if "kube-scheduler" in container.command:
                        # Check for --profiling=false
                        if "--profiling=false" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.4.1",
                                title="Ensure that the --profiling argument is set to false",
                                severity=AWSSeverity.MEDIUM,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
            
        except Exception as e:
            logger.error(f"Error checking control plane components: {str(e)}")
        
        return findings
    
    async def _check_etcd_configuration(self) -> List[AWSFinding]:
        """Check etcd configuration against CIS benchmarks."""
        findings = []
        
        try:
            # Check if etcd is running with TLS
            etcd_pods = self.core_v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=etcd"
            ).items
            
            for pod in etcd_pods:
                for container in pod.spec.containers:
                    if "etcd" in container.command:
                        # Check for --client-cert-auth=true
                        if "--client-cert-auth=true" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="2.1",
                                title="Ensure that the --client-cert-auth argument is set to true",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
                        
                        # Check for --auto-tls
                        if "--auto-tls=true" in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="2.2",
                                title="Ensure that the --auto-tls argument is not set to true",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
            
        except Exception as e:
            logger.error(f"Error checking etcd configuration: {str(e)}")
        
        return findings
    
    async def _check_control_plane_config(self) -> List[AWSFinding]:
        """Check control plane configuration against CIS benchmarks."""
        findings = []
        
        try:
            # Check API server configuration
            api_server_pods = self.core_v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            ).items
            
            for pod in api_server_pods:
                for container in pod.spec.containers:
                    if "kube-apiserver" in container.command:
                        # Check for --enable-admission-plugins=NodeRestriction
                        if "--enable-admission-plugins=NodeRestriction" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.2.19",
                                title="Ensure that the --enable-admission-plugins argument includes NodeRestriction",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
                        
                        # Check for --disable-admission-plugins=AlwaysAdmit
                        if "--disable-admission-plugins=AlwaysAdmit" not in " ".join(container.command):
                            findings.append(self._create_cis_finding(
                                id="1.2.21",
                                title="Ensure that the --disable-admission-plugins argument does not include AlwaysAdmit",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.name}"],
                                namespace="kube-system"
                            ))
            
            # Check kubelet configuration
            nodes = self.core_v1.list_node().items
            for node in nodes:
                kubelet_config = self.core_v1.read_node_proxy_with_path(f"{node.metadata.name}", "configz")
                if "kubeletconfig" in kubelet_config:
                    kubelet_config = kubelet_config["kubeletconfig"]
                    
                    # Check for read-only port
                    if kubelet_config.get("readOnlyPort", 0) != 0:
                        findings.append(self._create_cis_finding(
                            id="4.2.1",
                            title="Ensure that the --read-only-port argument is set to 0",
                            severity=AWSSeverity.HIGH,
                            resources=[f"node/{node.metadata.name}"],
                            namespace=None
                        ))
                    
                    # Check for protectKernelDefaults
                    if not kubelet_config.get("protectKernelDefaults", False):
                        findings.append(self._create_cis_finding(
                            id="4.2.6",
                            title="Ensure that the --protect-kernel-defaults argument is set to true",
                            severity=AWSSeverity.MEDIUM,
                            resources=[f"node/{node.metadata.name}"],
                            namespace=None
                        ))
            
        except Exception as e:
            logger.error(f"Error checking control plane configuration: {str(e)}")
        
        return findings
    
    async def _check_worker_nodes(self) -> List[AWSFinding]:
        """Check worker node configuration against CIS benchmarks."""
        findings = []
        
        try:
            # Check kubelet service configuration
            nodes = self.core_v1.list_node().items
            for node in nodes:
                # Check if kubelet is running with --anonymous-auth=false
                kubelet_config = self.core_v1.read_node_proxy_with_path(f"{node.metadata.name}", "configz")
                if "kubeletconfig" in kubelet_config:
                    kubelet_config = kubelet_config["kubeletconfig"]
                    
                    if kubelet_config.get("authentication", {}).get("anonymous", {}).get("enabled", True):
                        findings.append(self._create_cis_finding(
                            id="4.1.1",
                            title="Ensure that the --anonymous-auth argument is set to false",
                            severity=AWSSeverity.HIGH,
                            resources=[f"node/{node.metadata.name}"],
                            namespace=None
                        ))
                    
                    # Check for authorization mode
                    if kubelet_config.get("authorization", {}).get("mode", "").lower() != "webhook":
                        findings.append(self._create_cis_finding(
                            id="4.2.2",
                            title="Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                            severity=AWSSeverity.HIGH,
                            resources=[f"node/{node.metadata.name}"],
                            namespace=None
                        ))
            
        except Exception as e:
            logger.error(f"Error checking worker node configuration: {str(e)}")
        
        return findings
    
    async def _check_policies(self) -> List[AWSFinding]:
        """Check Kubernetes policies against CIS benchmarks."""
        findings = []
        
        try:
            # Check for default service accounts with tokens
            service_accounts = self.core_v1.list_service_account_for_all_namespaces().items
            for sa in service_accounts:
                if sa.metadata.name == 'default' and sa.automount_service_account_token is not False:
                    findings.append(self._create_cis_finding(
                        id="5.1.1",
                        title="Ensure that the default service account has no service account token",
                        severity=AWSSeverity.MEDIUM,
                        resources=[f"serviceaccount/{sa.metadata.namespace}/{sa.metadata.name}"],
                        namespace=sa.metadata.namespace
                    ))
            
            # Check for privileged containers
            pods = self.core_v1.list_pod_for_all_namespaces().items
            for pod in pods:
                for container in pod.spec.containers:
                    security_context = container.security_context
                    if security_context and security_context.privileged:
                        findings.append(self._create_cis_finding(
                            id="5.2.1",
                            title="Minimize the admission of privileged containers",
                            severity=AWSSeverity.HIGH,
                            resources=[f"pod/{pod.metadata.namespace}/{pod.metadata.name}"],
                            namespace=pod.metadata.namespace
                        ))
                        break
            
            # Check for host namespaces
            for pod in pods:
                if pod.spec.host_network or pod.spec.host_pid or pod.spec.host_ipc:
                    findings.append(self._create_cis_finding(
                        id="5.2.2",
                        title="Minimize the admission of containers wishing to share the host network namespace",
                        severity=AWSSeverity.HIGH,
                        resources=[f"pod/{pod.metadata.namespace}/{pod.metadata.name}"],
                        namespace=pod.metadata.namespace
                    ))
                    break
            
            # Check for hostPath volumes
            for pod in pods:
                if pod.spec.volumes:
                    for volume in pod.spec.volumes:
                        if volume.host_path:
                            findings.append(self._create_cis_finding(
                                id="5.2.3",
                                title="Minimize the admission of containers wishing to share the host process ID namespace",
                                severity=AWSSeverity.HIGH,
                                resources=[f"pod/{pod.metadata.namespace}/{pod.metadata.name}"],
                                namespace=pod.metadata.namespace
                            ))
                            break
            
            # Check network policies
            findings.extend(await self._validate_network_policies())
            
        except Exception as e:
            logger.error(f"Error checking policies: {str(e)}")
        
        return findings
        
    async def _validate_network_policies(self) -> List[AWSFinding]:
        """Validate network policies for security best practices.
        
        Returns:
            List of network policy validation findings
        """
        findings = []
        
        try:
            # Get all namespaces
            namespaces = self.core_v1.list_namespace().items
            
            for ns in namespaces:
                namespace = ns.metadata.name
                
                # Skip system namespaces
                if namespace in ["kube-system", "kube-public", "kube-node-lease"]:
                    continue
                
                # Get all network policies in the namespace
                try:
                    network_policies = self.networking_v1.list_namespaced_network_policy(namespace).items
                    
                    # Check if default deny policy exists
                    has_default_deny = any(
                        policy.spec.pod_selector == {} and 
                        not policy.spec.ingress and 
                        not policy.spec.egress
                        for policy in network_policies
                    )
                    
                    if not has_default_deny:
                        findings.append(self._create_network_policy_finding(
                            finding_type="MISSING_DEFAULT_DENY",
                            severity=AWSSeverity.HIGH,
                            namespace=namespace,
                            title=f"Namespace '{namespace}' is missing a default deny network policy",
                            description=(
                                "A default deny network policy should be applied to restrict all traffic "
                                "and only allow explicitly defined communication between pods."
                            ),
                            remediation=(
                                "Create a default deny network policy that denies all ingress and egress traffic "
                                "and then create additional policies to allow specific traffic as needed."
                            ),
                            example_policy="""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <namespace>
spec:
  pod_selector: {}
  policyTypes:
  - Ingress
  - Egress"""
                        ))
                    
                    # Check for permissive policies
                    for policy in network_policies:
                        # Check for overly permissive ingress
                        if policy.spec.ingress:
                            for i, rule in enumerate(policy.spec.ingress):
                                if not rule.ports and not rule.from_:
                                    findings.append(self._create_network_policy_finding(
                                        finding_type="PERMISSIVE_INGRESS",
                                        severity=AWSSeverity.HIGH,
                                        namespace=namespace,
                                        title=f"Overly permissive ingress rule in network policy '{policy.metadata.name}'",
                                        description=(
                                            f"The ingress rule at index {i} in network policy '{policy.metadata.name}' "
                                            "allows all traffic without any restrictions."
                                        ),
                                        remediation=(
                                            "Restrict ingress traffic by specifying allowed ports, protocols, "
                                            "and sources in the network policy."
                                        ),
                                        affected_resources=[f"networkpolicy/{namespace}/{policy.metadata.name}"]
                                    ))
                        
                        # Check for overly permissive egress
                        if policy.spec.egress:
                            for i, rule in enumerate(policy.spec.egress):
                                if not rule.ports and not rule.to:
                                    findings.append(self._create_network_policy_finding(
                                        finding_type="PERMISSIVE_EGRESS",
                                        severity=AWSSeverity.HIGH,
                                        namespace=namespace,
                                        title=f"Overly permissive egress rule in network policy '{policy.metadata.name}'",
                                        description=(
                                            f"The egress rule at index {i} in network policy '{policy.metadata.name}' "
                                            "allows all traffic without any restrictions."
                                        ),
                                        remediation=(
                                            "Restrict egress traffic by specifying allowed ports, protocols, "
                                            "and destinations in the network policy."
                                        ),
                                        affected_resources=[f"networkpolicy/{namespace}/{policy.metadata.name}"]
                                    ))
                    
                    # Check for missing network policies in namespaces with pods
                    if not network_policies and self._namespace_has_workloads(namespace):
                        findings.append(self._create_network_policy_finding(
                            finding_type="MISSING_NETWORK_POLICIES",
                            severity=AWSSeverity.MEDIUM,
                            namespace=namespace,
                            title=f"Namespace '{namespace}' has no network policies defined",
                            description=(
                                "The namespace contains workloads but has no network policies defined, "
                                "which may allow unrestricted network traffic."
                            ),
                            remediation=(
                                "Define network policies to restrict traffic between pods in this namespace "
                                "and from external sources."
                            )
                        ))
                
                except ApiException as e:
                    if e.status != 403:  # Skip if we don't have permission
                        logger.warning(f"Error checking network policies in namespace {namespace}: {str(e)}")
            
            # Check for cross-namespace traffic
            findings.extend(await self._check_cross_namespace_traffic())
            
        except Exception as e:
            logger.error(f"Error validating network policies: {str(e)}")
        
        return findings
        
    async def _check_cross_namespace_traffic(self) -> List[AWSFinding]:
        """Check for potentially dangerous cross-namespace traffic patterns.
        
        Returns:
            List of findings related to cross-namespace traffic
        """
        findings = []
        
        try:
            # Get all services in all namespaces
            services = self.core_v1.list_service_for_all_namespaces().items
            
            # Group services by namespace
            services_by_namespace = {}
            for svc in services:
                if svc.metadata.namespace not in services_by_namespace:
                    services_by_namespace[svc.metadata.namespace] = []
                services_by_namespace[svc.metadata.namespace].append(svc)
            
            # Check for services that are exposed to all namespaces
            for namespace, svc_list in services_by_namespace.items():
                for svc in svc_list:
                    # Check for services with type LoadBalancer or NodePort that might be exposed externally
                    if svc.spec.type in ["LoadBalancer", "NodePort"]:
                        # Check if there are network policies restricting access
                        has_restrictive_policy = False
                        try:
                            network_policies = self.networking_v1.list_namespaced_network_policy(namespace).items
                            for policy in network_policies:
                                # Check if this policy restricts access to the service
                                if self._policy_restricts_service_access(policy, svc):
                                    has_restrictive_policy = True
                                    break
                        except ApiException:
                            # If we can't check the policies, assume they don't exist
                            pass
                            
                        if not has_restrictive_policy:
                            findings.append(self._create_network_policy_finding(
                                finding_type="UNRESTRICTED_SERVICE_ACCESS",
                                severity=AWSSeverity.HIGH,
                                namespace=namespace,
                                title=f"Service '{svc.metadata.name}' is exposed externally without proper network restrictions",
                                description=(
                                    f"The service '{svc.metadata.name}' in namespace '{namespace}' is exposed via {svc.spec.type} "
                                    "but does not have network policies restricting access to it."
                                ),
                                remediation=(
                                    "Create network policies to restrict access to this service. "
                                    "Only allow ingress from trusted sources and required namespaces."
                                ),
                                affected_resources=[f"service/{namespace}/{svc.metadata.name}"]
                            ))
            
        except Exception as e:
            logger.error(f"Error checking cross-namespace traffic: {str(e)}")
        
        return findings
    
    def _namespace_has_workloads(self, namespace: str) -> bool:
        """Check if a namespace contains any workloads (pods, deployments, etc.).
        
        Args:
            namespace: The namespace to check
            
        Returns:
            bool: True if the namespace contains workloads, False otherwise
        """
        try:
            # Check for pods
            pods = self.core_v1.list_namespaced_pod(namespace).items
            if pods:
                return True
                
            # Check for deployments
            deployments = self.apps_v1.list_namespaced_deployment(namespace).items
            if deployments:
                return True
                
            # Check for statefulsets
            statefulsets = self.apps_v1.list_namespaced_stateful_set(namespace).items
            if statefulsets:
                return True
                
            # Check for daemonsets
            daemonsets = self.apps_v1.list_namespaced_daemon_set(namespace).items
            if daemonsets:
                return True
                
            return False
            
        except Exception as e:
            logger.warning(f"Error checking workloads in namespace {namespace}: {str(e)}")
            return False
    
    def _policy_restricts_service_access(self, policy, service) -> bool:
        """Check if a network policy restricts access to a service.
        
        Args:
            policy: The NetworkPolicy object
            service: The Service object
            
        Returns:
            bool: True if the policy restricts access to the service, False otherwise
        """
        # If the policy has ingress rules, check if they restrict access to the service
        if hasattr(policy.spec, 'ingress') and policy.spec.ingress:
            # Check if the policy applies to the service's pods
            if self._policy_applies_to_service(policy, service):
                # Check if the ingress rules are restrictive
                for rule in policy.spec.ingress:
                    # If any rule allows all sources, it's not restrictive
                    if not rule.from_:
                        return False
                    # If any rule allows from all namespaces, it's not restrictive
                    for source in rule.from_:
                        if hasattr(source, 'namespace_selector') and source.namespace_selector and \
                           source.namespace_selector.match_labels is None:
                            return False
                return True
        return False
    
    def _policy_applies_to_service(self, policy, service) -> bool:
        """Check if a network policy applies to a service's pods.
        
        Args:
            policy: The NetworkPolicy object
            service: The Service object
            
        Returns:
            bool: True if the policy applies to the service's pods, False otherwise
        """
        # If the policy applies to all pods in the namespace, it applies to the service
        if not hasattr(policy.spec.pod_selector, 'match_labels') or not policy.spec.pod_selector.match_labels:
            return True
            
        # Get the service's selector
        if not hasattr(service.spec, 'selector') or not service.spec.selector:
            return False
            
        # Check if the policy's pod selector matches the service's pod selector
        service_selector = service.spec.selector
        policy_selector = policy.spec.pod_selector.match_labels
        
        # If all labels in the policy's selector match the service's selector, it applies
        return all(k in service_selector and service_selector[k] == v 
                  for k, v in policy_selector.items())
    
    def _create_network_policy_finding(
        self,
        finding_type: str,
        severity: AWSSeverity,
        namespace: str,
        title: str,
        description: str,
        remediation: str,
        affected_resources: Optional[List[str]] = None,
        example_policy: Optional[str] = None
    ) -> AWSFinding:
        """Create a standardized network policy finding.
        
        Args:
            finding_type: Type of the finding (e.g., "MISSING_DEFAULT_DENY")
            severity: Severity level
            namespace: Namespace where the finding was detected
            title: Title of the finding
            description: Detailed description
            remediation: Remediation steps
            affected_resources: List of affected resources
            example_policy: Example policy YAML (optional)
            
        Returns:
            AWSFinding object
        """
        if affected_resources is None:
            affected_resources = []
            
        details = {
            "namespace": namespace,
            "affected_resources": affected_resources,
            "remediation_steps": remediation
        }
        
        if example_policy:
            details["example_policy"] = example_policy
        
        return AWSFinding(
            service=AWSService.EKS,
            resource_id=affected_resources[0] if affected_resources else f"namespace/{namespace}",
            finding_type=f"NETWORK_POLICY_{finding_type}",
            severity=severity,
            description=title,
            details=details,
            remediation=remediation,
            references=[
                "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
                "https://www.cisecurity.org/benchmark/kubernetes/"
            ]
        )
    
    def _create_cis_finding(
        self,
        id: str,
        title: str,
        severity: AWSSeverity,
        resources: List[str],
        namespace: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> AWSFinding:
        """Create a standardized CIS benchmark finding.
        
        Args:
            id: CIS benchmark ID (e.g., "1.2.1")
            title: Title of the finding
            severity: Severity level
            resources: List of affected resources
            namespace: Namespace of the resource (if applicable)
            details: Additional details about the finding
            
        Returns:
            AWSFinding object
        """
        if details is None:
            details = {}
            
        description = f"CIS Benchmark {id}: {title}"
        
        # Add CIS reference
        references = [
            f"https://www.cisecurity.org/benchmark/kubernetes/"
        ]
        
        # Create remediation based on CIS ID
        remediation = self._get_cis_remediation(id)
        
        return AWSFinding(
            service=AWSService.EKS,
            resource_id=resources[0] if resources else "cluster",
            finding_type=f"CIS_{id.replace('.', '_')}",
            severity=severity,
            description=description,
            details={
                **details,
                "cis_id": id,
                "cis_title": title,
                "resources": resources,
                "namespace": namespace
            },
            remediation=remediation,
            references=references
        )
    
    def _get_cis_remediation(self, cis_id: str) -> str:
        """Get remediation steps for a CIS benchmark ID.
        
        Args:
            cis_id: CIS benchmark ID (e.g., "1.2.1")
            
        Returns:
            Remediation steps as a string
        """
        # Map of CIS IDs to remediation steps
        remediation_map = {
            # Control Plane Components
            "1.2.1": "Set the --anonymous-auth flag to false in the kube-apiserver.yaml file.",
            "1.2.7": "Edit the API server pod specification file and set the --authorization-mode parameter to 'Node,RBAC'.",
            "1.2.18": "Edit the API server pod specification file and set the --audit-log-path parameter to an appropriate path.",
            "1.2.20": "Edit the API server pod specification file and set the --audit-log-maxage parameter to 30 or as appropriate.",
            "1.3.1": "Edit the Controller Manager pod specification file and set the --use-service-account-credentials parameter to true.",
            "1.3.2": "Edit the Controller Manager pod specification file and set the --feature-gates parameter to include RotateKubeletServerCertificate=true.",
            "1.4.1": "Edit the Scheduler pod specification file and set the --profiling parameter to false.",
            
            # etcd Configuration
            "2.1": "Edit the etcd pod specification file and set the --client-cert-auth parameter to true.",
            "2.2": "Edit the etcd pod specification file and ensure the --auto-tls parameter is not set to true.",
            
            # Control Plane Configuration
            "1.2.19": "Edit the API server pod specification file and set the --enable-admission-plugins parameter to include NodeRestriction.",
            "1.2.21": "Edit the API server pod specification file and ensure the --disable-admission-plugins parameter does not include AlwaysAdmit.",
            "4.2.1": "Edit the kubelet service file and set the --read-only-port parameter to 0.",
            "4.2.6": "Edit the kubelet service file and set the --protect-kernel-defaults parameter to true.",
            
            # Worker Nodes
            "4.1.1": "Edit the kubelet service file and set the --anonymous-auth parameter to false.",
            "4.2.2": "Edit the kubelet service file and ensure the --authorization-mode parameter is not set to AlwaysAllow.",
            
            # Policies
            "5.1.1": "Create explicit service accounts for each pod and avoid using the default service account.",
            "5.2.1": "Create and enforce policies that prevent the creation of privileged containers.",
            "5.2.2": "Create and enforce policies that prevent pods from using host namespaces.",
            "5.2.3": "Create and enforce policies that prevent the use of hostPath volumes.",
        }
        
        return remediation_map.get(cis_id, "Refer to the CIS Kubernetes Benchmark for remediation steps.")
