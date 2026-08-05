//! Kubernetes Cloud Connector Implementation
//! 
//! Provides comprehensive scanning capabilities for Kubernetes clusters including:
//! - Pods, Deployments, Services, ConfigMaps, Secrets, RBAC
//! - Real-time configuration fetching via Kubernetes API
//! - Namespace and cluster handling
//! - Resource normalization to CloudGhidra internal models

use async_trait::async_trait;
use k8s_openapi::api::{
    apps::v1::{Deployment, DaemonSet, StatefulSet, ReplicaSet},
    core::v1::{Pod, Service, ConfigMap, Secret, Namespace, Node, PersistentVolumeClaim, PersistentVolume, ServiceAccount},
    rbac::v1::{Role, ClusterRole, RoleBinding, ClusterRoleBinding},
    networking::v1::{Ingress, NetworkPolicy},
};
use kube::{
    api::{Api, ListParams, ResourceExt},
    client::Client as KubeClient,
    config::{KubeConfigOptions, load_from_default_home_dir},
    Client, Config,
};
use tracing::{info, warn, instrument, error};
use std::collections::HashMap;
use std::sync::Arc;

use crate::models::{
    CloudProvider, ResourceType, CloudResource, ResourceMetadata, Tag,
};
use crate::traits::CloudConnector;
use crate::error::{CloudGhidraError, Result};

/// Configuration for Kubernetes Connector
#[derive(Debug, Clone)]
pub struct KubeConnectorConfig {
    pub kubeconfig_path: Option<String>,
    pub context: Option<String>,
    pub namespace: Option<String>,
    pub scan_all_namespaces: bool,
    pub scan_timeout_secs: u64,
    pub include_sensitive: bool, // Include secrets and sensitive configs
}

impl Default for KubeConnectorConfig {
    fn default() -> Self {
        Self {
            kubeconfig_path: None,
            context: None,
            namespace: Some("default".to_string()),
            scan_all_namespaces: true,
            scan_timeout_secs: 300,
            include_sensitive: false,
        }
    }
}

/// Kubernetes Cloud Connector
pub struct KubeConnector {
    config: KubeConnectorConfig,
    client: Option<Client>,
    is_connected: bool,
}

impl KubeConnector {
    /// Create a new Kubernetes connector with default configuration
    pub fn new() -> Self {
        Self::with_config(KubeConnectorConfig::default())
    }

    /// Create a new Kubernetes connector with custom configuration
    pub fn with_config(config: KubeConnectorConfig) -> Self {
        Self {
            config,
            client: None,
            is_connected: false,
        }
    }

    /// Initialize Kubernetes client
    #[instrument(skip(self))]
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to Kubernetes cluster...");
        
        let config = if let Some(kubeconfig) = &self.config.kubeconfig_path {
            let kubeconfig_options = KubeConfigOptions {
                context: self.config.context.clone(),
                ..Default::default()
            };
            Config::from_custom_kubeconfig(
                load_from_default_home_dir()
                    .await
                    .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to load kubeconfig: {}", e)))?,
                &kubeconfig_options,
            )
            .await
            .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to create kube config: {}", e)))?
        } else {
            Config::infer()
                .await
                .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to infer kube config: {}", e)))?
        };

        let client = Client::try_from(config)
            .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to create Kubernetes client: {}", e)))?;

        self.client = Some(client);
        self.is_connected = true;
        info!("Successfully connected to Kubernetes cluster");
        Ok(())
    }

    /// Scan Pods
    #[instrument(skip(self))]
    async fn scan_pods(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
            let pod_list = pods_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list pods in {}: {}", namespace, e)))?;

            for pod in pod_list.items {
                let pod_name = pod.name_any();
                let resource_id = format!("k8s://pod/{}/{}", namespace, pod_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::Container);
                metadata.set_property("namespace", namespace.clone());
                
                // Status
                if let Some(status) = &pod.status {
                    if let Some(phase) = &status.phase {
                        metadata.set_property("phase", phase.clone());
                    }
                    if let Some(host_ip) = &status.host_ip {
                        metadata.set_property("host_ip", host_ip.clone());
                    }
                    if let Some(pod_ip) = &status.pod_ip {
                        metadata.set_property("pod_ip", pod_ip.clone());
                    }
                    
                    // Container statuses
                    if let Some(container_statuses) = &status.container_statuses {
                        let mut container_images = Vec::new();
                        let mut ready_count = 0;
                        
                        for cs in container_statuses {
                            container_images.push(cs.image.clone());
                            if cs.ready {
                                ready_count += 1;
                            }
                        }
                        
                        metadata.set_property("container_images", serde_json::to_string(&container_images)?);
                        metadata.set_property("ready_containers", format!("{}/{}", ready_count, container_statuses.len()));
                    }
                }
                
                // Spec
                if let Some(spec) = &pod.spec {
                    // Service Account
                    if let Some(sa) = &spec.service_account_name {
                        metadata.set_property("service_account", sa.clone());
                    }
                    
                    // Node name
                    if let Some(node) = &spec.node_name {
                        metadata.set_property("node", node.clone());
                    }
                    
                    // Restart policy
                    if let Some(restart_policy) = &spec.restart_policy {
                        metadata.set_property("restart_policy", restart_policy.clone());
                    }
                    
                    // Host network
                    if let Some(host_network) = spec.host_network {
                        metadata.set_property("host_network", host_network.to_string());
                    }
                    
                    // Host PID
                    if let Some(host_pid) = spec.host_pid {
                        metadata.set_property("host_pid", host_pid.to_string());
                    }
                    
                    // Host IPC
                    if let Some(host_ipc) = spec.host_ipc {
                        metadata.set_property("host_ipc", host_ipc.to_string());
                    }
                    
                    // Containers
                    let mut container_names = Vec::new();
                    let mut container_images = Vec::new();
                    let mut has_privileged = false;
                    let mut has_root_user = false;
                    
                    for container in &spec.containers {
                        container_names.push(container.name.clone());
                        container_images.push(container.image.clone());
                        
                        // Check security context
                        if let Some(security_context) = &container.security_context {
                            if let Some(privileged) = security_context.privileged {
                                if privileged {
                                    has_privileged = true;
                                }
                            }
                            if let Some(run_as_user) = security_context.run_as_user {
                                if run_as_user == 0 {
                                    has_root_user = true;
                                }
                            }
                        }
                        
                        // Check volume mounts for sensitive paths
                        if let Some(volume_mounts) = &container.volume_mounts {
                            let sensitive_mounts: Vec<String> = volume_mounts.iter()
                                .filter(|vm| {
                                    vm.mount_path.starts_with("/var/run/secrets") ||
                                    vm.mount_path.starts_with("/etc/shadow") ||
                                    vm.mount_path.starts_with("/etc/passwd")
                                })
                                .map(|vm| vm.mount_path.clone())
                                .collect();
                            
                            if !sensitive_mounts.is_empty() {
                                metadata.set_property("sensitive_mounts", serde_json::to_string(&sensitive_mounts)?);
                            }
                        }
                    }
                    
                    metadata.set_property("container_names", serde_json::to_string(&container_names)?);
                    metadata.set_property("container_images", serde_json::to_string(&container_images)?);
                    metadata.set_property("has_privileged_container", has_privileged.to_string());
                    metadata.set_property("has_root_user", has_root_user.to_string());
                    
                    // Volumes
                    if let Some(volumes) = &spec.volumes {
                        let mut volume_types = Vec::new();
                        let mut has_host_path = false;
                        let mut has_secret_volume = false;
                        let mut has_configmap_volume = false;
                        
                        for volume in volumes {
                            if volume.host_path.is_some() {
                                has_host_path = true;
                                if let Some(hp) = &volume.host_path {
                                    volume_types.push(format!("hostPath:{}", hp.path.clone().unwrap_or_else(|| "unknown".to_string())));
                                }
                            }
                            if volume.secret.is_some() {
                                has_secret_volume = true;
                                volume_types.push("secret".to_string());
                            }
                            if volume.config_map.is_some() {
                                has_configmap_volume = true;
                                volume_types.push("configMap".to_string());
                            }
                            if volume.persistent_volume_claim.is_some() {
                                if let Some(pvc) = &volume.persistent_volume_claim {
                                    volume_types.push(format!("pvc:{}", pvc.claim_name));
                                }
                            }
                        }
                        
                        metadata.set_property("volume_types", serde_json::to_string(&volume_types)?);
                        metadata.set_property("has_host_path", has_host_path.to_string());
                        metadata.set_property("has_secret_volume", has_secret_volume.to_string());
                        metadata.set_property("has_configmap_volume", has_configmap_volume.to_string());
                    }
                }
                
                // Labels
                if let Some(labels) = &pod.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }
                
                // Annotations
                if let Some(annotations) = &pod.metadata.annotations {
                    metadata.set_property("annotations", serde_json::to_string(annotations)?);
                }

                let resource = CloudResource::new(
                    resource_id,
                    pod_name,
                    ResourceType::Container,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan Deployments
    #[instrument(skip(self))]
    async fn scan_deployments(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
            let deployment_list = deployments_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list deployments in {}: {}", namespace, e)))?;

            for deployment in deployment_list.items {
                let deployment_name = deployment.name_any();
                let resource_id = format!("k8s://deployment/{}/{}", namespace, deployment_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::ContainerOrchestration);
                metadata.set_property("namespace", namespace.clone());
                
                // Spec
                if let Some(spec) = &deployment.spec {
                    // Replicas
                    if let Some(replicas) = spec.replicas {
                        metadata.set_property("desired_replicas", replicas.to_string());
                    }
                    
                    // Strategy
                    if let Some(strategy) = &spec.strategy {
                        if let Some(type_) = &strategy.type_ {
                            metadata.set_property("strategy_type", type_.clone());
                        }
                    }
                    
                    // Selector
                    if let Some(selector) = &spec.selector {
                        let match_labels = selector.match_labels.unwrap_or_default();
                        metadata.set_property("selector_labels", serde_json::to_string(&match_labels)?);
                    }
                    
                    // Template
                    if let Some(template) = &spec.template {
                        if let Some(spec) = &template.spec {
                            // Service Account
                            if let Some(sa) = &spec.service_account_name {
                                metadata.set_property("service_account", sa.clone());
                            }
                            
                            // Containers
                            let mut container_images = Vec::new();
                            for container in &spec.containers {
                                container_images.push(container.image.clone());
                                
                                // Check resource requests/limits
                                if let Some(resources) = &container.resources {
                                    let mut resource_info = HashMap::new();
                                    
                                    if let Some(requests) = &resources.requests {
                                        if let Some(cpu) = requests.get("cpu") {
                                            resource_info.insert("request_cpu", cpu.0.clone());
                                        }
                                        if let Some(memory) = requests.get("memory") {
                                            resource_info.insert("request_memory", memory.0.clone());
                                        }
                                    }
                                    
                                    if let Some(limits) = &resources.limits {
                                        if let Some(cpu) = limits.get("cpu") {
                                            resource_info.insert("limit_cpu", cpu.0.clone());
                                        }
                                        if let Some(memory) = limits.get("memory") {
                                            resource_info.insert("limit_memory", memory.0.clone());
                                        }
                                    }
                                    
                                    if !resource_info.is_empty() {
                                        metadata.set_property("resources", serde_json::to_string(&resource_info)?);
                                    }
                                }
                            }
                            
                            metadata.set_property("container_images", serde_json::to_string(&container_images)?);
                        }
                    }
                }
                
                // Status
                if let Some(status) = &deployment.status {
                    if let Some(available_replicas) = status.available_replicas {
                        metadata.set_property("available_replicas", available_replicas.to_string());
                    }
                    if let Some(ready_replicas) = status.ready_replicas {
                        metadata.set_property("ready_replicas", ready_replicas.to_string());
                    }
                    if let Some(unavailable_replicas) = status.unavailable_replicas {
                        metadata.set_property("unavailable_replicas", unavailable_replicas.to_string());
                    }
                }
                
                // Labels
                if let Some(labels) = &deployment.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }

                let resource = CloudResource::new(
                    resource_id,
                    deployment_name,
                    ResourceType::ContainerOrchestration,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan Services
    #[instrument(skip(self))]
    async fn scan_services(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let services_api: Api<Service> = Api::namespaced(client.clone(), namespace);
            let service_list = services_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list services in {}: {}", namespace, e)))?;

            for service in service_list.items {
                let service_name = service.name_any();
                let resource_id = format!("k8s://service/{}/{}", namespace, service_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::LoadBalancer);
                metadata.set_property("namespace", namespace.clone());
                
                // Spec
                if let Some(spec) = &service.spec {
                    // Type
                    if let Some(type_) = &spec.type_ {
                        metadata.set_property("type", type_.clone());
                        metadata.set_property("is_load_balancer", (type_ == "LoadBalancer").to_string());
                        metadata.set_property("is_node_port", (type_ == "NodePort").to_string());
                    }
                    
                    // Cluster IP
                    if let Some(cluster_ip) = &spec.cluster_ip {
                        metadata.set_property("cluster_ip", cluster_ip.clone());
                    }
                    
                    // External IPs
                    if let Some(external_ips) = &spec.external_ips {
                        if !external_ips.is_empty() {
                            metadata.set_property("external_ips", serde_json::to_string(external_ips)?);
                        }
                    }
                    
                    // Load Balancer IP
                    if let Some(load_balancer_ip) = &spec.load_balancer_ip {
                        metadata.set_property("load_balancer_ip", load_balancer_ip.clone());
                    }
                    
                    // Ports
                    let mut port_info = Vec::new();
                    for port in &spec.ports {
                        let mut port_data = HashMap::new();
                        port_data.insert("name", port.name.clone().unwrap_or_else(|| "unnamed".to_string()));
                        port_data.insert("port", port.port.to_string());
                        if let Some(target_port) = &port.target_port {
                            port_data.insert("target_port", target_port.to_string());
                        }
                        if let Some(node_port) = port.node_port {
                            port_data.insert("node_port", node_port.to_string());
                        }
                        port_data.insert("protocol", port.protocol.clone().unwrap_or_else(|| "TCP".to_string()));
                        port_info.push(port_data);
                    }
                    metadata.set_property("ports", serde_json::to_string(&port_info)?);
                    
                    // Selector
                    if let Some(selector) = &spec.selector {
                        metadata.set_property("selector", serde_json::to_string(selector)?);
                    }
                    
                    // External Traffic Policy
                    if let Some(external_traffic_policy) = &spec.external_traffic_policy {
                        metadata.set_property("external_traffic_policy", external_traffic_policy.clone());
                    }
                    
                    // Internal Traffic Policy
                    if let Some(internal_traffic_policy) = &spec.internal_traffic_policy {
                        metadata.set_property("internal_traffic_policy", internal_traffic_policy.clone());
                    }
                }
                
                // Status - Load Balancer Ingress
                if let Some(status) = &service.status {
                    if let Some(lb_status) = &status.load_balancer {
                        if let Some(ingress) = &lb_status.ingress {
                            let ingress_info: Vec<String> = ingress.iter()
                                .filter_map(|i| {
                                    if let Some(ip) = &i.ip {
                                        Some(ip.clone())
                                    } else if let Some(hostname) = &i.hostname {
                                        Some(hostname.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            
                            if !ingress_info.is_empty() {
                                metadata.set_property("load_balancer_ingress", serde_json::to_string(&ingress_info)?);
                            }
                        }
                    }
                }
                
                // Labels
                if let Some(labels) = &service.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }

                let resource = CloudResource::new(
                    resource_id,
                    service_name,
                    ResourceType::LoadBalancer,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan ConfigMaps
    #[instrument(skip(self))]
    async fn scan_configmaps(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let cms_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
            let cm_list = cms_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list configmaps in {}: {}", namespace, e)))?;

            for cm in cm_list.items {
                let cm_name = cm.name_any();
                let resource_id = format!("k8s://configmap/{}/{}", namespace, cm_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::Configuration);
                metadata.set_property("namespace", namespace.clone());
                
                // Data keys
                if let Some(data) = &cm.data {
                    let keys: Vec<String> = data.keys().cloned().collect();
                    metadata.set_property("data_keys", serde_json::to_string(&keys)?);
                    metadata.set_property("data_count", keys.len().to_string());
                    
                    // Check for potentially sensitive keys
                    let sensitive_patterns = ["password", "secret", "key", "token", "credential", "api_key", "apikey"];
                    let sensitive_keys: Vec<String> = keys.iter()
                        .filter(|k| {
                            let lower = k.to_lowercase();
                            sensitive_patterns.iter().any(|p| lower.contains(p))
                        })
                        .cloned()
                        .collect();
                    
                    if !sensitive_keys.is_empty() {
                        metadata.set_property("potentially_sensitive_keys", serde_json::to_string(&sensitive_keys)?);
                    }
                }
                
                // Binary data keys
                if let Some(binary_data) = &cm.binary_data {
                    let keys: Vec<String> = binary_data.keys().cloned().collect();
                    metadata.set_property("binary_data_keys", serde_json::to_string(&keys)?);
                    metadata.set_property("binary_data_count", keys.len().to_string());
                }
                
                // Labels
                if let Some(labels) = &cm.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }

                let resource = CloudResource::new(
                    resource_id,
                    cm_name,
                    ResourceType::Configuration,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan Secrets (only if include_sensitive is enabled)
    #[instrument(skip(self))]
    async fn scan_secrets(&self) -> Result<Vec<CloudResource>> {
        if !self.config.include_sensitive {
            return Ok(Vec::new());
        }

        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
            let secret_list = secrets_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list secrets in {}: {}", namespace, e)))?;

            for secret in secret_list.items {
                let secret_name = secret.name_any();
                let resource_id = format!("k8s://secret/{}/{}", namespace, secret_name);
                
                let secret_type = secret.type_.clone().unwrap_or_else(|| "Opaque".to_string());
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::SecretManager);
                metadata.set_property("namespace", namespace.clone());
                metadata.set_property("secret_type", secret_type);
                
                // Data keys (not values for security)
                if let Some(data) = &secret.data {
                    let keys: Vec<String> = data.keys().cloned().collect();
                    metadata.set_property("data_keys", serde_json::to_string(&keys)?);
                    metadata.set_property("data_count", keys.len().to_string());
                }
                
                // String data keys
                if let Some(string_data) = &secret.string_data {
                    let keys: Vec<String> = string_data.keys().cloned().collect();
                    metadata.set_property("string_data_keys", serde_json::to_string(&keys)?);
                    metadata.set_property("string_data_count", keys.len().to_string());
                }
                
                // Labels
                if let Some(labels) = &secret.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }
                
                // Annotations
                if let Some(annotations) = &secret.metadata.annotations {
                    metadata.set_property("annotations", serde_json::to_string(annotations)?);
                }

                let resource = CloudResource::new(
                    resource_id,
                    secret_name,
                    ResourceType::SecretManager,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan RBAC Roles and ClusterRoles
    #[instrument(skip(self))]
    async fn scan_rbac_roles(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        // Scan Namespaced Roles
        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let roles_api: Api<Role> = Api::namespaced(client.clone(), namespace);
            let role_list = roles_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list roles in {}: {}", namespace, e)))?;

            for role in role_list.items {
                let role_name = role.name_any();
                let resource_id = format!("k8s://role/{}/{}", namespace, role_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::IamRole);
                metadata.set_property("namespace", namespace.clone());
                metadata.set_property("role_type", "Role");
                
                // Rules
                if let Some(rules) = &role.rules {
                    let mut api_groups = Vec::new();
                    let mut resources_list = Vec::new();
                    let mut verbs_list = Vec::new();
                    let mut has_wildcard = false;
                    let mut has_sensitive_verbs = false;
                    
                    for rule in rules {
                        if let Some(groups) = &rule.api_groups {
                            api_groups.extend(groups.clone());
                        }
                        if let Some(resources) = &rule.resources {
                            resources_list.extend(resources.clone());
                        }
                        if let Some(verbs) = &rule.verbs {
                            verbs_list.extend(verbs.clone());
                            
                            // Check for wildcard or sensitive verbs
                            if verbs.iter().any(|v| v == "*") {
                                has_wildcard = true;
                            }
                            if verbs.iter().any(|v| {
                                v == "create" || v == "delete" || v == "update" || v == "patch" || v == "*"
                            }) {
                                has_sensitive_verbs = true;
                            }
                        }
                    }
                    
                    metadata.set_property("api_groups", serde_json::to_string(&api_groups)?);
                    metadata.set_property("resources", serde_json::to_string(&resources_list)?);
                    metadata.set_property("verbs", serde_json::to_string(&verbs_list)?);
                    metadata.set_property("has_wildcard_permissions", has_wildcard.to_string());
                    metadata.set_property("has_sensitive_verbs", has_sensitive_verbs.to_string());
                    metadata.set_property("rule_count", rules.len().to_string());
                }
                
                // Labels
                if let Some(labels) = &role.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }

                let resource = CloudResource::new(
                    resource_id,
                    role_name,
                    ResourceType::IamRole,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        // Scan ClusterRoles
        let cluster_roles_api: Api<ClusterRole> = Api::all(client.clone());
        let cluster_role_list = cluster_roles_api.list(&ListParams::default()).await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list clusterroles: {}", e)))?;

        for cluster_role in cluster_role_list.items {
            let role_name = cluster_role.name_any();
            let resource_id = format!("k8s://clusterrole/{}", role_name);
            
            let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::IamRole);
            metadata.set_property("namespace", "cluster-wide");
            metadata.set_property("role_type", "ClusterRole");
            
            // Rules
            if let Some(rules) = &cluster_role.rules {
                let mut api_groups = Vec::new();
                let mut resources_list = Vec::new();
                let mut verbs_list = Vec::new();
                let mut has_wildcard = false;
                let mut has_sensitive_verbs = false;
                let mut has_cluster_admin = false;
                
                for rule in rules {
                    if let Some(groups) = &rule.api_groups {
                        api_groups.extend(groups.clone());
                    }
                    if let Some(resources) = &rule.resources {
                        resources_list.extend(resources.clone());
                    }
                    if let Some(verbs) = &rule.verbs {
                        verbs_list.extend(verbs.clone());
                        
                        if verbs.iter().any(|v| v == "*") {
                            has_wildcard = true;
                        }
                        if verbs.iter().any(|v| {
                            v == "create" || v == "delete" || v == "update" || v == "patch" || v == "*"
                        }) {
                            has_sensitive_verbs = true;
                        }
                    }
                    
                    // Check for cluster-admin-like permissions
                    if rule.resources.as_ref().map(|r| r.iter().any(|res| res == "*")).unwrap_or(false) &&
                       rule.verbs.as_ref().map(|v| v.iter().any(|verb| verb == "*")).unwrap_or(false) {
                        has_cluster_admin = true;
                    }
                }
                
                metadata.set_property("api_groups", serde_json::to_string(&api_groups)?);
                metadata.set_property("resources", serde_json::to_string(&resources_list)?);
                metadata.set_property("verbs", serde_json::to_string(&verbs_list)?);
                metadata.set_property("has_wildcard_permissions", has_wildcard.to_string());
                metadata.set_property("has_sensitive_verbs", has_sensitive_verbs.to_string());
                metadata.set_property("has_cluster_admin_permissions", has_cluster_admin.to_string());
                metadata.set_property("rule_count", rules.len().to_string());
            }
            
            // Aggregation rules
            if let Some(aggregation_rule) = &cluster_role.aggregation_rule {
                if let Some(labels) = &aggregation_rule.cluster_role_selectors {
                    metadata.set_property("aggregation_labels", serde_json::to_string(labels)?);
                }
            }
            
            // Labels
            if let Some(labels) = &cluster_role.metadata.labels {
                for (key, value) in labels.iter() {
                    metadata.add_tag(Tag::new(key.clone(), value.clone()));
                }
            }

            let resource = CloudResource::new(
                resource_id,
                role_name,
                ResourceType::IamRole,
                metadata,
            );
            
            resources.push(resource);
        }

        Ok(resources)
    }

    /// Scan ServiceAccounts
    #[instrument(skip(self))]
    async fn scan_service_accounts(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
            let sa_list = sa_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list serviceaccounts in {}: {}", namespace, e)))?;

            for sa in sa_list.items {
                let sa_name = sa.name_any();
                let resource_id = format!("k8s://serviceaccount/{}/{}", namespace, sa_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::IamUser);
                metadata.set_property("namespace", namespace.clone());
                
                // Secrets
                if let Some(secrets) = &sa.secrets {
                    let secret_names: Vec<String> = secrets.iter()
                        .map(|s| s.name.clone())
                        .collect();
                    
                    if !secret_names.is_empty() {
                        metadata.set_property("secrets", serde_json::to_string(&secret_names)?);
                        metadata.set_property("secret_count", secret_names.len().to_string());
                    }
                }
                
                // Image pull secrets
                if let Some(image_pull_secrets) = &sa.image_pull_secrets {
                    let ips_names: Vec<String> = image_pull_secrets.iter()
                        .map(|s| s.name.clone())
                        .collect();
                    
                    if !ips_names.is_empty() {
                        metadata.set_property("image_pull_secrets", serde_json::to_string(&ips_names)?);
                    }
                }
                
                // Automount service account token
                if let Some(automount) = sa.automount_service_account_token {
                    metadata.set_property("automount_token", automount.to_string());
                }
                
                // Labels
                if let Some(labels) = &sa.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }
                
                // Annotations
                if let Some(annotations) = &sa.metadata.annotations {
                    metadata.set_property("annotations", serde_json::to_string(annotations)?);
                }

                let resource = CloudResource::new(
                    resource_id,
                    sa_name,
                    ResourceType::IamUser,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan NetworkPolicies
    #[instrument(skip(self))]
    async fn scan_network_policies(&self) -> Result<Vec<CloudResource>> {
        let client = self.client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let namespaces = if self.config.scan_all_namespaces {
            let ns_api: Api<Namespace> = Api::all(client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list namespaces: {}", e)))?;
            
            ns_list.items.iter().map(|ns| ns.name_any()).collect::<Vec<_>>()
        } else {
            vec![self.config.namespace.clone().unwrap_or_else(|| "default".to_string())]
        };

        for namespace in &namespaces {
            let np_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
            let np_list = np_api.list(&ListParams::default()).await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list networkpolicies in {}: {}", namespace, e)))?;

            for np in np_list.items {
                let np_name = np.name_any();
                let resource_id = format!("k8s://networkpolicy/{}/{}", namespace, np_name);
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Kubernetes, ResourceType::SecurityGroup);
                metadata.set_property("namespace", namespace.clone());
                
                // Spec
                if let Some(spec) = &np.spec {
                    // Pod selector
                    if let Some(pod_selector) = &spec.pod_selector {
                        if let Some(match_labels) = pod_selector.match_labels {
                            metadata.set_property("pod_selector_labels", serde_json::to_string(&match_labels)?);
                        }
                    }
                    
                    // Policy types
                    if let Some(policy_types) = &spec.policy_types {
                        metadata.set_property("policy_types", serde_json::to_string(policy_types)?);
                        metadata.set_property("has_ingress_policy", policy_types.iter().any(|t| t == "Ingress"));
                        metadata.set_property("has_egress_policy", policy_types.iter().any(|t| t == "Egress"));
                    }
                    
                    // Ingress rules
                    if let Some(ingress_rules) = &spec.ingress {
                        metadata.set_property("ingress_rule_count", ingress_rules.len().to_string());
                        
                        let mut has_allow_all = false;
                        for rule in ingress_rules {
                            if rule.from.is_none() {
                                has_allow_all = true;
                            }
                        }
                        metadata.set_property("has_allow_all_ingress", has_allow_all.to_string());
                    }
                    
                    // Egress rules
                    if let Some(egress_rules) = &spec.egress {
                        metadata.set_property("egress_rule_count", egress_rules.len().to_string());
                        
                        let mut has_allow_all = false;
                        for rule in egress_rules {
                            if rule.from.is_none() {
                                has_allow_all = true;
                            }
                        }
                        metadata.set_property("has_allow_all_egress", has_allow_all.to_string());
                    }
                }
                
                // Labels
                if let Some(labels) = &np.metadata.labels {
                    for (key, value) in labels.iter() {
                        metadata.add_tag(Tag::new(key.clone(), value.clone()));
                    }
                }

                let resource = CloudResource::new(
                    resource_id,
                    np_name,
                    ResourceType::SecurityGroup,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }
}

#[async_trait]
impl CloudConnector for KubeConnector {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Kubernetes
    }

    fn is_connected(&self) -> bool {
        self.is_connected
    }

    async fn connect_async(&mut self) -> Result<()> {
        self.connect().await
    }

    async fn disconnect_async(&mut self) -> Result<()> {
        self.client = None;
        self.is_connected = false;
        info!("Disconnected from Kubernetes cluster");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn scan_resources(&self, resource_types: Option<Vec<ResourceType>>) -> Result<Vec<CloudResource>> {
        if !self.is_connected {
            return Err(CloudGhidraError::NotConnected);
        }

        let mut all_resources = Vec::new();
        let target_types = resource_types.unwrap_or_else(|| vec![
            ResourceType::Container,
            ResourceType::ContainerOrchestration,
            ResourceType::LoadBalancer,
            ResourceType::Configuration,
            ResourceType::SecretManager,
            ResourceType::IamRole,
            ResourceType::IamUser,
            ResourceType::SecurityGroup,
        ]);

        if target_types.contains(&ResourceType::Container) {
            match self.scan_pods().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes pods", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes pods: {}", e),
            }
        }

        if target_types.contains(&ResourceType::ContainerOrchestration) {
            match self.scan_deployments().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes deployments", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes deployments: {}", e),
            }
        }

        if target_types.contains(&ResourceType::LoadBalancer) {
            match self.scan_services().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes services", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes services: {}", e),
            }
        }

        if target_types.contains(&ResourceType::Configuration) {
            match self.scan_configmaps().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes configmaps", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes configmaps: {}", e),
            }
        }

        if target_types.contains(&ResourceType::SecretManager) && self.config.include_sensitive {
            match self.scan_secrets().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes secrets", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes secrets: {}", e),
            }
        }

        if target_types.contains(&ResourceType::IamRole) {
            match self.scan_rbac_roles().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes RBAC roles", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes RBAC roles: {}", e),
            }
        }

        if target_types.contains(&ResourceType::IamUser) {
            match self.scan_service_accounts().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes service accounts", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes service accounts: {}", e),
            }
        }

        if target_types.contains(&ResourceType::SecurityGroup) {
            match self.scan_network_policies().await {
                Ok(resources) => {
                    info!("Scanned {} Kubernetes network policies", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Kubernetes network policies: {}", e),
            }
        }

        Ok(all_resources)
    }

    async fn validate_credentials(&self) -> Result<bool> {
        Ok(self.is_connected)
    }

    async fn get_metadata(&self) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "Kubernetes".to_string());
        metadata.insert("connected".to_string(), self.is_connected.to_string());
        metadata.insert("scan_all_namespaces".to_string(), self.config.scan_all_namespaces.to_string());
        metadata.insert("include_sensitive".to_string(), self.config.include_sensitive.to_string());
        if let Some(ns) = &self.config.namespace {
            metadata.insert("namespace".to_string(), ns.clone());
        }
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kube_connector_creation() {
        let connector = KubeConnector::new();
        assert_eq!(connector.provider(), CloudProvider::Kubernetes);
        assert!(!connector.is_connected());
    }

    #[tokio::test]
    async fn test_kube_connector_config() {
        let config = KubeConnectorConfig {
            kubeconfig_path: Some("~/.kube/config".to_string()),
            context: Some("dev-cluster".to_string()),
            namespace: Some("production".to_string()),
            scan_all_namespaces: false,
            include_sensitive: true,
            ..Default::default()
        };
        let connector = KubeConnector::with_config(config);
        assert_eq!(connector.provider(), CloudProvider::Kubernetes);
    }
}
