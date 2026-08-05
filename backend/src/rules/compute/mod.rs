// CloudLens - Compute Security Rules Module (Complete)
// Comprehensive compute instance and serverless security rules
// Part of the 40K lines security rules implementation

use crate::models::{SecurityRule, SecurityRisk, RiskSeverity, RiskCategory, CloudResource, ResourceType};
use crate::traits::SecurityRuleTrait;
use async_trait::async_trait;
use std::collections::HashMap;

/// Rule: Instance Without IMDSv2
pub struct InstanceWithoutIMDSv2Rule;

#[async_trait]
impl SecurityRuleTrait for InstanceWithoutIMDSv2Rule {
    fn id(&self) -> &'static str { "COMP-001" }
    fn name(&self) -> &'static str { "Instance Without IMDSv2" }
    fn description(&self) -> &'static str { 
        "EC2 instance does not enforce IMDSv2, allowing SSRF attacks to access instance metadata" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::InstanceMetadata }
    fn cwe_id(&self) -> &'static str { "CWE-918" }
    fn mitre_id(&self) -> &'static str { "T1550.005" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::VM {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let imds_version = config.get("imds_version")
            .and_then(|v| v.as_str())
            .unwrap_or("v1");
        
        let http_tokens_required = config.get("http_tokens_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if imds_version != "v2" || !http_tokens_required {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "VM {} does not enforce IMDSv2 (current: {})",
                    resource.name, imds_version
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable IMDSv2 with http_tokens_required=true to prevent SSRF attacks".to_string(),
                metadata: HashMap::from([
                    ("imds_version".to_string(), imds_version.to_string()),
                    ("http_tokens_required".to_string(), http_tokens_required.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Overly Permissive Security Group on Instance
pub struct OverlyPermissiveInstanceSGRule;

#[async_trait]
impl SecurityRuleTrait for OverlyPermissiveInstanceSGRule {
    fn id(&self) -> &'static str { "COMP-002" }
    fn name(&self) -> &'static str { "Overly Permissive Security Group on Instance" }
    fn description(&self) -> &'static str { 
        "VM has security group allowing unrestricted access to all ports" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::VM {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let security_groups = config.get("security_groups")
            .and_then(|v| v.as_array());
        
        if let Some(sgs) = security_groups {
            for sg in sgs {
                let sg_obj = sg.as_object()?;
                let ingress = sg_obj.get("ingress_rules")
                    .and_then(|v| v.as_array());
                
                if let Some(rules) = ingress {
                    for rule in rules {
                        let rule_obj = rule.as_object()?;
                        let cidr = rule_obj.get("cidr_block")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let from_port = rule_obj.get("from_port")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let to_port = rule_obj.get("to_port")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(65535);
                        
                        if (cidr == "0.0.0.0/0" || cidr == "::/0") 
                            && from_port == 0 
                            && to_port == 65535 
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
                                    "VM {} has security group allowing all ports from {}",
                                    resource.name, cidr
                                ),
                                cwe_id: self.cwe_id().to_string(),
                                mitre_id: self.mitre_id().to_string(),
                                remediation: "Restrict security group rules to specific ports and IP ranges".to_string(),
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        
        None
    }
}

/// Rule: Instance Without Monitoring
pub struct InstanceWithoutMonitoringRule;

#[async_trait]
impl SecurityRuleTrait for InstanceWithoutMonitoringRule {
    fn id(&self) -> &'static str { "COMP-003" }
    fn name(&self) -> &'static str { "Instance Without Monitoring" }
    fn description(&self) -> &'static str { 
        "VM does not have detailed monitoring or logging agents enabled" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::VM {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let monitoring_enabled = config.get("monitoring_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_ssm_agent = config.get("ssm_agent_installed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_cloudwatch_agent = config.get("cloudwatch_agent_installed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !monitoring_enabled && !has_ssm_agent && !has_cloudwatch_agent {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "VM {} lacks monitoring and logging agents",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Install SSM agent and enable detailed monitoring for visibility".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Lambda Function With Excessive Permissions
pub struct LambdaExcessivePermissionsRule;

#[async_trait]
impl SecurityRuleTrait for LambdaExcessivePermissionsRule {
    fn id(&self) -> &'static str { "COMP-004" }
    fn name(&self) -> &'static str { "Lambda Function With Excessive Permissions" }
    fn description(&self) -> &'static str { 
        "Serverless function has overly permissive IAM role with unnecessary privileges" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::PrivilegeEscalation }
    fn cwe_id(&self) -> &'static str { "CWE-269" }
    fn mitre_id(&self) -> &'static str { "T1078" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Function {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let attached_policies = config.get("attached_policies")
            .and_then(|v| v.as_array());
        
        if let Some(policies) = attached_policies {
            let dangerous_policies = [
                "AdministratorAccess",
                "IAMFullAccess",
                "*FullAccess",
                "arn:aws:iam::aws:policy/AdministratorAccess"
            ];
            
            let has_dangerous = policies.iter().any(|p| {
                let policy = p.as_str().unwrap_or("");
                dangerous_policies.iter().any(|dp| policy.contains(dp))
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
                        "Lambda function {} has excessive IAM permissions",
                        resource.name
                    ),
                    cwe_id: self.cwe_id().to_string(),
                    mitre_id: self.mitre_id().to_string(),
                    remediation: "Apply principle of least privilege to Lambda execution role".to_string(),
                    metadata: HashMap::new(),
                });
            }
        }
        
        None
    }
}

/// Rule: Container Running in Privileged Mode
pub struct ContainerPrivilegedModeRule;

#[async_trait]
impl SecurityRuleTrait for ContainerPrivilegedModeRule {
    fn id(&self) -> &'static str { "COMP-005" }
    fn name(&self) -> &'static str { "Container Running in Privileged Mode" }
    fn description(&self) -> &'static str { 
        "Container runs in privileged mode, granting full host access" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::ContainerSecurity }
    fn cwe_id(&self) -> &'static str { "CWE-250" }
    fn mitre_id(&self) -> &'static str { "T1611" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Container {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let privileged = config.get("privileged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if privileged {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Container {} runs in privileged mode",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Remove privileged flag and use specific capabilities instead".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Outdated AMI or Container Image
pub struct OutdatedImageRule;

#[async_trait]
impl SecurityRuleTrait for OutdatedImageRule {
    fn id(&self) -> &'static str { "COMP-006" }
    fn name(&self) -> &'static str { "Outdated AMI/Container Image" }
    fn description(&self) -> &'static str { 
        "VM or container uses outdated image with known vulnerabilities" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::VulnerabilityManagement }
    fn cwe_id(&self) -> &'static str { "CWE-1104" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::VM 
            && resource.resource_type != ResourceType::Container
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let image_age_days = config.get("image_age_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        let critical_vulns_count = config.get("critical_vulnerabilities_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        if image_age_days > 90 || critical_vulns_count > 0 {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "{} {} uses outdated image ({} days old, {} critical vulns)",
                    resource.resource_type, resource.name, image_age_days, critical_vulns_count
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Update to latest patched image and implement regular update cycle".to_string(),
                metadata: HashMap::from([
                    ("image_age_days".to_string(), image_age_days.to_string()),
                    ("critical_vulns".to_string(), critical_vulns_count.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Missing Resource Tags
pub struct MissingResourceTagsRule;

#[async_trait]
impl SecurityRuleTrait for MissingResourceTagsRule {
    fn id(&self) -> &'static str { "COMP-007" }
    fn name(&self) -> &'static str { "Missing Resource Tags" }
    fn description(&self) -> &'static str { 
        "Compute resource lacks required tags for governance and cost allocation" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Low }
    fn category(&self) -> RiskCategory { RiskCategory::Governance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::VM 
            && resource.resource_type != ResourceType::Function
            && resource.resource_type != ResourceType::Container
        {
            return None;
        }

        let required_tags = ["environment", "owner", "cost_center", "application"];
        let missing_tags: Vec<&str> = required_tags
            .iter()
            .filter(|tag| !resource.tags.contains_key(*tag))
            .copied()
            .collect();
        
        if !missing_tags.is_empty() {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} missing required tags: {:?}",
                    resource.name, missing_tags
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Add required tags for proper governance and cost tracking".to_string(),
                metadata: HashMap::from([
                    ("missing_tags".to_string(), missing_tags.join(", ")),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Auto-scaling Without Health Checks
pub struct AutoscalingWithoutHealthCheckRule;

#[async_trait]
impl SecurityRuleTrait for AutoscalingWithoutHealthCheckRule {
    fn id(&self) -> &'static str { "COMP-008" }
    fn name(&self) -> &'static str { "Auto-scaling Without Health Checks" }
    fn description(&self) -> &'static str { 
        "Auto-scaling group does not have proper health checks configured" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Availability }
    fn cwe_id(&self) -> &'static str { "CWE-693" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::AutoScalingGroup {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let health_check_enabled = config.get("health_check_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let health_check_grace_period = config.get("health_check_grace_period")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        if !health_check_enabled || health_check_grace_period < 300 {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Auto-scaling group {} has inadequate health checks",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable ELB health checks with appropriate grace period (>=300s)".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Unencrypted EBS Volume
pub struct UnencryptedEBSVolumeRule;

#[async_trait]
impl SecurityRuleTrait for UnencryptedEBSVolumeRule {
    fn id(&self) -> &'static str { "COMP-009" }
    fn name(&self) -> &'static str { "Unencrypted EBS Volume" }
    fn description(&self) -> &'static str { 
        "EBS volume is not encrypted at rest" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::DataProtection }
    fn cwe_id(&self) -> &'static str { "CWE-311" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Volume {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let encrypted = config.get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !encrypted {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "EBS volume {} is not encrypted",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption for EBS volumes using KMS keys".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Public Snapshot
pub struct PublicSnapshotRule;

#[async_trait]
impl SecurityRuleTrait for PublicSnapshotRule {
    fn id(&self) -> &'static str { "COMP-010" }
    fn name(&self) -> &'static str { "Public Snapshot" }
    fn description(&self) -> &'static str { 
        "EBS snapshot or AMI is publicly shared" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::DataExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1530" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Snapshot 
            && resource.resource_type != ResourceType::Image
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let public = config.get("public")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let contains_sensitive = config.get("contains_sensitive_data")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if public {
            let severity = if contains_sensitive {
                RiskSeverity::Critical
            } else {
                RiskSeverity::High
            };
            
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity,
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "{} {} is publicly shared",
                    resource.resource_type, resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Make snapshot private or share only with specific accounts".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

// Export all compute security rules
pub fn get_compute_rules() -> Vec<Box<dyn SecurityRuleTrait + Send + Sync>> {
    vec![
        Box::new(InstanceWithoutIMDSv2Rule),
        Box::new(OverlyPermissiveInstanceSGRule),
        Box::new(InstanceWithoutMonitoringRule),
        Box::new(LambdaExcessivePermissionsRule),
        Box::new(ContainerPrivilegedModeRule),
        Box::new(OutdatedImageRule),
        Box::new(MissingResourceTagsRule),
        Box::new(AutoscalingWithoutHealthCheckRule),
        Box::new(UnencryptedEBSVolumeRule),
        Box::new(PublicSnapshotRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_imdsv2_rule() {
        let rule = InstanceWithoutIMDSv2Rule;
        let resource = CloudResource {
            id: "i-test".to_string(),
            name: "test-instance".to_string(),
            resource_type: ResourceType::VM,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "imds_version": "v1",
                "http_tokens_required": false,
                "security_groups": [],
                "monitoring_enabled": false
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
    async fn test_privileged_container_rule() {
        let rule = ContainerPrivilegedModeRule;
        let resource = CloudResource {
            id: "container-test".to_string(),
            name: "privileged-container".to_string(),
            resource_type: ResourceType::Container,
            provider: crate::models::CloudProvider::Kubernetes,
            region: "us-east-1".to_string(),
            configuration: json!({
                "privileged": true,
                "image": "nginx:latest",
                "ports": []
            }),
            tags: HashMap::from([
                ("environment".to_string(), "production".to_string()),
                ("owner".to_string(), "team-a".to_string()),
                ("cost_center".to_string(), "cc-123".to_string()),
                ("application".to_string(), "web".to_string()),
            ]),
            created_at: None,
            updated_at: None,
        };

        let result = rule.evaluate(&resource).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, RiskSeverity::Critical);
    }
}
