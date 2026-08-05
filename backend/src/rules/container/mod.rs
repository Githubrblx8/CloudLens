// CloudLens - Container Security Rules Module
// Comprehensive container and Kubernetes security rules
// Part of the 40K lines security rules implementation

use crate::models::{SecurityRule, SecurityRisk, RiskSeverity, RiskCategory, CloudResource, ResourceType};
use crate::traits::SecurityRuleTrait;
use async_trait::async_trait;
use std::collections::HashMap;

/// Rule: Container Running as Root
pub struct ContainerRunningAsRootRule;

#[async_trait]
impl SecurityRuleTrait for ContainerRunningAsRootRule {
    fn id(&self) -> &'static str { "CONT-001" }
    fn name(&self) -> &'static str { "Container Running as Root" }
    fn description(&self) -> &'static str { 
        "Container runs as root user, increasing impact of container escape" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-250" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Container {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let run_as_root = config.get("run_as_root")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let user = config.get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        if run_as_root || user == "root" || user == "0" {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Container {} runs as root user",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Configure container to run as non-root user with minimal privileges".to_string(),
                metadata: HashMap::from([
                    ("user".to_string(), user.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Missing Pod Security Policy/Standards
pub struct MissingPodSecurityRule;

#[async_trait]
impl SecurityRuleTrait for MissingPodSecurityRule {
    fn id(&self) -> &'static str { "CONT-002" }
    fn name(&self) -> &'static str { "Missing Pod Security Policy/Standards" }
    fn description(&self) -> &'static str { 
        "Namespace does not enforce Pod Security Standards or Policies" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Namespace {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_pss = config.get("pod_security_standards")
            .and_then(|v| v.as_str())
            .is_some();
        
        let has_psp = config.get("pod_security_policy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let enforcement_level = config.get("enforcement_level")
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        
        if !has_pss && !has_psp && enforcement_level == "none" {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Namespace {} lacks Pod Security Standards enforcement",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable Pod Security Standards with 'restricted' or 'baseline' profile".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Host Network Access
pub struct HostNetworkAccessRule;

#[async_trait]
impl SecurityRuleTrait for HostNetworkAccessRule {
    fn id(&self) -> &'static str { "CONT-003" }
    fn name(&self) -> &'static str { "Host Network Access" }
    fn description(&self) -> &'static str { 
        "Pod uses host network namespace, bypassing network isolation" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Pod {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let host_network = config.get("host_network")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if host_network {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Pod {} uses host network namespace",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Remove hostNetwork: true and use proper Kubernetes networking".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Host PID Namespace
pub struct HostPIDNamespaceRule;

#[async_trait]
impl SecurityRuleTrait for HostPIDNamespaceRule {
    fn id(&self) -> &'static str { "CONT-004" }
    fn name(&self) -> &'static str { "Host PID Namespace" }
    fn description(&self) -> &'static str { 
        "Pod shares host PID namespace, allowing process visibility and signaling" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Pod {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let host_pid = config.get("host_pid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if host_pid {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Pod {} shares host PID namespace",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Remove hostPID: true to maintain process isolation".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Writable Root Filesystem
pub struct WritableRootFilesystemRule;

#[async_trait]
impl SecurityRuleTrait for WritableRootFilesystemRule {
    fn id(&self) -> &'static str { "CONT-005" }
    fn name(&self) -> &'static str { "Writable Root Filesystem" }
    fn description(&self) -> &'static str { 
        "Container has writable root filesystem, allowing malware persistence" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Container {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let read_only_root = config.get("read_only_root_filesystem")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !read_only_root {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Container {} has writable root filesystem",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Set readOnlyRootFilesystem: true and use volumes for writes".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Dangerous Capabilities
pub struct DangerousCapabilitiesRule;

#[async_trait]
impl SecurityRuleTrait for DangerousCapabilitiesRule {
    fn id(&self) -> &'static str { "CONT-006" }
    fn name(&self) -> &'static str { "Dangerous Capabilities" }
    fn description(&self) -> &'static str { 
        "Container has dangerous Linux capabilities enabled" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-250" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Container {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let capabilities = config.get("capabilities")
            .and_then(|v| v.as_array());
        
        if let Some(caps) = capabilities {
            let dangerous_caps = [
                "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                "DAC_READ_SEARCH", "NET_RAW", "SYS_RAWIO", "ALL"
            ];
            
            let has_dangerous = caps.iter().any(|c| {
                let cap = c.as_str().unwrap_or("");
                dangerous_caps.iter().any(|dc| cap.contains(dc))
            });
            
            if has_dangerous {
                return Some(SecurityRisk {
                    id: format!("{}-{}", self.id(), resource.id),
                    rule_id: self.id().to_string(),
                    resource_id: resource.id.clone(),
                    resource_type: resource.resource_type.clone(),
                    severity: self.severity(),
                    category: self.category(),
                    title: self.name().to_string(),
                    description: format!(
                        "Container {} has dangerous Linux capabilities",
                        resource.name
                    ),
                    cwe_id: self.cwe_id().to_string(),
                    mitre_id: self.mitre_id().to_string(),
                    remediation: "Drop all capabilities and add only required ones".to_string(),
                    metadata: HashMap::new(),
                });
            }
        }
        
        None
    }
}

/// Rule: Missing Resource Limits
pub struct MissingResourceLimitsRule;

#[async_trait]
impl SecurityRuleTrait for MissingResourceLimitsRule {
    fn id(&self) -> &'static str { "CONT-007" }
    fn name(&self) -> &'static str { "Missing Resource Limits" }
    fn description(&self) -> &'static str { 
        "Container lacks CPU/memory limits, risking resource exhaustion" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Availability }
    fn cwe_id(&self) -> &'static str { "CWE-400" }
    fn mitre_id(&self) -> &'static str { "T1499" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Container 
            && resource.resource_type != ResourceType::Pod
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_cpu_limit = config.get("cpu_limit")
            .and_then(|v| v.as_str())
            .is_some();
        
        let has_memory_limit = config.get("memory_limit")
            .and_then(|v| v.as_str())
            .is_some();
        
        if !has_cpu_limit || !has_memory_limit {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Container {} lacks resource limits (CPU: {}, Memory: {})",
                    resource.name,
                    if has_cpu_limit { "set" } else { "missing" },
                    if has_memory_limit { "set" } else { "missing" }
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Define CPU and memory limits in pod spec".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Image Pull Policy Always Not Set
pub struct ImagePullPolicyRule;

#[async_trait]
impl SecurityRuleTrait for ImagePullPolicyRule {
    fn id(&self) -> &'static str { "CONT-008" }
    fn name(&self) -> &'static str { "Image Pull Policy Not Set" }
    fn description(&self) -> &'static str { 
        "Container image pull policy may allow using cached vulnerable images" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Low }
    fn category(&self) -> RiskCategory { RiskCategory::VulnerabilityManagement }
    fn cwe_id(&self) -> &'static str { "CWE-1104" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Container {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let image_tag = config.get("image")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        let pull_policy = config.get("image_pull_policy")
            .and_then(|v| v.as_str())
            .unwrap_or("IfNotPresent");
        
        // If using latest tag without Always policy, or using mutable tags
        if (image_tag.contains(":latest") || image_tag.contains(":main") || image_tag.contains(":master"))
            && pull_policy != "Always" 
        {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Container {} uses mutable tag '{}' without Always pull policy",
                    resource.name, image_tag
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Use immutable image tags or set imagePullPolicy: Always".to_string(),
                metadata: HashMap::from([
                    ("image".to_string(), image_tag.to_string()),
                    ("pull_policy".to_string(), pull_policy.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Service Account Token Auto-Mounted
pub struct ServiceAccountTokenAutoMountRule;

#[async_trait]
impl SecurityRuleTrait for ServiceAccountTokenAutoMountRule {
    fn id(&self) -> &'static str { "CONT-009" }
    fn name(&self) -> &'static str { "Service Account Token Auto-Mounted" }
    fn description(&self) -> &'static str { 
        "Pod auto-mounts service account token, potentially exposing credentials" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::SecretsManagement }
    fn cwe_id(&self) -> &'static str { "CWE-522" }
    fn mitre_id(&self) -> &'static str { "T1552.005" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Pod {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let automount_token = config.get("automount_service_account_token")
            .and_then(|v| v.as_bool())
            .unwrap_or(true); // Default is true in Kubernetes
        
        let needs_api_access = config.get("needs_kubernetes_api_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if automount_token && !needs_api_access {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Pod {} auto-mounts service account token unnecessarily",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Set automountServiceAccountToken: false unless API access is required".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Ingress Without TLS
pub struct IngressWithoutTLSRule;

#[async_trait]
impl SecurityRuleTrait for IngressWithoutTLSRule {
    fn id(&self) -> &'static str { "CONT-010" }
    fn name(&self) -> &'static str { "Ingress Without TLS" }
    fn description(&self) -> &'static str { 
        "Kubernetes Ingress exposes services without TLS encryption" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Encryption }
    fn cwe_id(&self) -> &'static str { "CWE-319" }
    fn mitre_id(&self) -> &'static str { "T1040" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Ingress {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_tls = config.get("tls_configured")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let tls_hosts = config.get("tls_hosts")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        
        let rules_count = config.get("rules_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        if !has_tls || tls_hosts == 0 {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Ingress {} exposes {} rules without TLS",
                    resource.name, rules_count
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Configure TLS with valid certificates for all ingress hosts".to_string(),
                metadata: HashMap::from([
                    ("tls_configured".to_string(), has_tls.to_string()),
                    ("rules_count".to_string(), rules_count.to_string()),
                ]),
            });
        }
        
        None
    }
}

// Export all container security rules
pub fn get_container_rules() -> Vec<Box<dyn SecurityRuleTrait + Send + Sync>> {
    vec![
        Box::new(ContainerRunningAsRootRule),
        Box::new(MissingPodSecurityRule),
        Box::new(HostNetworkAccessRule),
        Box::new(HostPIDNamespaceRule),
        Box::new(WritableRootFilesystemRule),
        Box::new(DangerousCapabilitiesRule),
        Box::new(MissingResourceLimitsRule),
        Box::new(ImagePullPolicyRule),
        Box::new(ServiceAccountTokenAutoMountRule),
        Box::new(IngressWithoutTLSRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_root_container_rule() {
        let rule = ContainerRunningAsRootRule;
        let resource = CloudResource {
            id: "pod-test".to_string(),
            name: "root-pod".to_string(),
            resource_type: ResourceType::Container,
            provider: crate::models::CloudProvider::Kubernetes,
            region: "default".to_string(),
            configuration: json!({
                "run_as_root": true,
                "user": "root",
                "image": "nginx:latest"
            }),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
        };

        let result = rule.evaluate(&resource).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, RiskSeverity::High);
    }

    #[tokio::test]
    async fn test_host_network_rule() {
        let rule = HostNetworkAccessRule;
        let resource = CloudResource {
            id: "pod-hostnet".to_string(),
            name: "host-network-pod".to_string(),
            resource_type: ResourceType::Pod,
            provider: crate::models::CloudProvider::Kubernetes,
            region: "default".to_string(),
            configuration: json!({
                "host_network": true,
                "host_pid": false,
                "containers": []
            }),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
        };

        let result = rule.evaluate(&resource).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, RiskSeverity::Critical);
    }
}
