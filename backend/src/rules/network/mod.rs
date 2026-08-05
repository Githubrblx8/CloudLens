// CloudGhidra - Network Security Rules Module
// Comprehensive network security analysis rules for cloud infrastructure
// Part of the 40K lines security rules implementation

use crate::models::{SecurityRule, SecurityRisk, RiskSeverity, RiskCategory, CloudResource, ResourceType};
use crate::traits::SecurityRuleTrait;
use async_trait::async_trait;
use std::collections::HashMap;

/// Rule: Publicly Accessible Security Group
pub struct PublicSecurityGroupRule;

#[async_trait]
impl SecurityRuleTrait for PublicSecurityGroupRule {
    fn id(&self) -> &'static str { "NET-001" }
    fn name(&self) -> &'static str { "Publicly Accessible Security Group" }
    fn description(&self) -> &'static str { 
        "Security group allows unrestricted inbound access from 0.0.0.0/0 on sensitive ports" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::SecurityGroup {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let ingress_rules = config.get("ingress_rules")?.as_array()?;
        
        let sensitive_ports = vec![22, 3389, 1433, 3306, 5432, 27017, 6379];
        
        for rule in ingress_rules {
            let rule_obj = rule.as_object()?;
            let cidr = rule_obj.get("cidr_block")?.as_str()?;
            
            if cidr == "0.0.0.0/0" || cidr == "::/0" {
                let port = rule_obj.get("from_port")?.as_u64()?;
                if sensitive_ports.contains(&(port as u16)) {
                    return Some(SecurityRisk {
                        id: format!("{}-{}", self.id(), resource.id),
                        rule_id: self.id().to_string(),
                        resource_id: resource.id.clone(),
                        resource_type: resource.resource_type.clone(),
                        severity: self.severity(),
                        category: self.category(),
                        title: self.name().to_string(),
                        description: format!(
                            "Security group {} allows public access to port {} from {}",
                            resource.name, port, cidr
                        ),
                        cwe_id: self.cwe_id().to_string(),
                        mitre_id: self.mitre_id().to_string(),
                        remediation: "Restrict security group ingress to specific IP ranges or VPC CIDR blocks".to_string(),
                        metadata: HashMap::from([
                            ("port".to_string(), port.to_string()),
                            ("cidr".to_string(), cidr.to_string()),
                        ]),
                    });
                }
            }
        }
        
        None
    }
}

/// Rule: Unrestricted Outbound Access
pub struct UnrestrictedEgressRule;

#[async_trait]
impl SecurityRuleTrait for UnrestrictedEgressRule {
    fn id(&self) -> &'static str { "NET-002" }
    fn name(&self) -> &'static str { "Unrestricted Outbound Access" }
    fn description(&self) -> &'static str { 
        "Security group allows unrestricted outbound traffic to any destination" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1041" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::SecurityGroup {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let egress_rules = config.get("egress_rules")?.as_array()?;
        
        if egress_rules.is_empty() {
            return None;
        }

        for rule in egress_rules {
            let rule_obj = rule.as_object()?;
            let cidr = rule_obj.get("cidr_block")?.as_str()?;
            let to_port = rule_obj.get("to_port")?.as_u64()?;
            
            if (cidr == "0.0.0.0/0" || cidr == "::/0") && to_port == 65535 {
                return Some(SecurityRisk {
                    id: format!("{}-{}", self.id(), resource.id),
                    rule_id: self.id().to_string(),
                    resource_id: resource.id.clone(),
                    resource_type: resource.resource_type.clone(),
                    severity: self.severity(),
                    category: self.category(),
                    title: self.name().to_string(),
                    description: format!(
                        "Security group {} allows unrestricted outbound traffic to all ports",
                        resource.name
                    ),
                    cwe_id: self.cwe_id().to_string(),
                    mitre_id: self.mitre_id().to_string(),
                    remediation: "Implement egress filtering to allow only necessary outbound traffic".to_string(),
                    metadata: HashMap::new(),
                });
            }
        }
        
        None
    }
}

/// Rule: Missing Network ACLs
pub struct MissingNACLRule;

#[async_trait]
impl SecurityRuleTrait for MissingNACLRule {
    fn id(&self) -> &'static str { "NET-003" }
    fn name(&self) -> &'static str { "Missing Network ACLs" }
    fn description(&self) -> &'static str { 
        "Subnet does not have explicit network ACLs configured, using permissive defaults" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Subnet {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_nacls = config.get("network_acls").is_some();
        
        if !has_nacls {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Subnet {} does not have explicit network ACLs configured",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Configure explicit network ACLs with deny-by-default policies".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Overlapping CIDR Blocks
pub struct OverlappingCIDRRule;

#[async_trait]
impl SecurityRuleTrait for OverlappingCIDRRule {
    fn id(&self) -> &'static str { "NET-004" }
    fn name(&self) -> &'static str { "Overlapping CIDR Blocks" }
    fn description(&self) -> &'static str { 
        "VPC or subnet CIDR blocks overlap causing routing conflicts" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Misconfiguration }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        // This rule requires cross-resource analysis
        // Simplified implementation for single resource check
        if resource.resource_type != ResourceType::VPC {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let cidr = config.get("cidr_block")?.as_str()?;
        
        // Check for overly broad CIDR that might overlap
        if cidr.ends_with("/8") || cidr.ends_with("/16") {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "VPC {} has a broad CIDR block {} that may cause routing conflicts",
                    resource.name, cidr
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Use more specific CIDR blocks and ensure no overlaps between VPCs".to_string(),
                metadata: HashMap::from([
                    ("cidr".to_string(), cidr.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Missing VPC Flow Logs
pub struct MissingFlowLogsRule;

#[async_trait]
impl SecurityRuleTrait for MissingFlowLogsRule {
    fn id(&self) -> &'static str { "NET-005" }
    fn name(&self) -> &'static str { "Missing VPC Flow Logs" }
    fn description(&self) -> &'static str { 
        "VPC does not have flow logs enabled for network traffic monitoring" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::VPC {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_flow_logs = config.get("flow_logs_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !has_flow_logs {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "VPC {} does not have flow logs enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable VPC flow logs to monitor network traffic for security analysis".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Public Load Balancer with Sensitive Backend
pub struct PublicLBWithSensitiveBackendRule;

#[async_trait]
impl SecurityRuleTrait for PublicLBWithSensitiveBackendRule {
    fn id(&self) -> &'static str { "NET-006" }
    fn name(&self) -> &'static str { "Public Load Balancer with Sensitive Backend" }
    fn description(&self) -> &'static str { 
        "Public load balancer routes traffic to backend instances with sensitive data" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::LoadBalancer {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let is_public = config.get("scheme")
            .and_then(|v| v.as_str())
            .map(|s| s == "internet-facing")
            .unwrap_or(false);
        
        if !is_public {
            return None;
        }

        let target_sensitive = config.get("backend_sensitive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if target_sensitive {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Public load balancer {} routes to backends containing sensitive data",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Move sensitive backends behind private load balancers or implement additional authentication".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Missing WAF Protection
pub struct MissingWAFRule;

#[async_trait]
impl SecurityRuleTrait for MissingWAFRule {
    fn id(&self) -> &'static str { "NET-007" }
    fn name(&self) -> &'static str { "Missing WAF Protection" }
    fn description(&self) -> &'static str { 
        "Public-facing application does not have Web Application Firewall protection" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::LoadBalancer 
            && resource.resource_type != ResourceType::APIGateway 
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_waf = config.get("waf_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let is_public = config.get("public")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        
        if is_public && !has_waf {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Public-facing resource {} lacks Web Application Firewall protection",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable WAF with OWASP Core Rule Set to protect against common web attacks".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Insecure Protocol Usage
pub struct InsecureProtocolRule;

#[async_trait]
impl SecurityRuleTrait for InsecureProtocolRule {
    fn id(&self) -> &'static str { "NET-008" }
    fn name(&self) -> &'static str { "Insecure Protocol Usage" }
    fn description(&self) -> &'static str { 
        "Resource uses deprecated or insecure protocols (HTTP, FTP, Telnet)" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Encryption }
    fn cwe_id(&self) -> &'static str { "CWE-319" }
    fn mitre_id(&self) -> &'static str { "T1040" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let protocol = config.get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        let insecure_protocols = ["http", "ftp", "telnet", "rsh", "rlogin"];
        
        if insecure_protocols.contains(&protocol.to_lowercase().as_str()) {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} uses insecure protocol: {}",
                    resource.name, protocol
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Migrate to secure protocols (HTTPS, SFTP, SSH)".to_string(),
                metadata: HashMap::from([
                    ("protocol".to_string(), protocol.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: DNS Misconfiguration
pub struct DNSMisconfigurationRule;

#[async_trait]
impl SecurityRuleTrait for DNSMisconfigurationRule {
    fn id(&self) -> &'static str { "NET-009" }
    fn name(&self) -> &'static str { "DNS Misconfiguration" }
    fn description(&self) -> &'static str { 
        "DNS configuration exposes internal infrastructure or allows zone transfers" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::InformationDisclosure }
    fn cwe_id(&self) -> &'static str { "CWE-200" }
    fn mitre_id(&self) -> &'static str { "T1590" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::DNSZone {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let allow_zone_transfer = config.get("allow_zone_transfer")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_internal_records_exposed = config.get("internal_records_public")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if allow_zone_transfer || has_internal_records_exposed {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "DNS zone {} has misconfigurations exposing internal information",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Disable zone transfers and remove internal DNS records from public zones".to_string(),
                metadata: HashMap::from([
                    ("zone_transfer".to_string(), allow_zone_transfer.to_string()),
                    ("internal_exposed".to_string(), has_internal_records_exposed.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Missing Network Segmentation
pub struct MissingSegmentationRule;

#[async_trait]
impl SecurityRuleTrait for MissingSegmentationRule {
    fn id(&self) -> &'static str { "NET-010" }
    fn name(&self) -> &'static str { "Missing Network Segmentation" }
    fn description(&self) -> &'static str { 
        "Critical resources are not properly segmented from less trusted networks" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::NetworkExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Database 
            && resource.resource_type != ResourceType::SecretsManager
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let is_in_private_subnet = config.get("private_subnet")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_public_access = config.get("publicly_accessible")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !is_in_private_subnet || has_public_access {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Critical resource {} lacks proper network segmentation",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Place critical resources in private subnets with strict access controls".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

// Export all network rules
pub fn get_network_rules() -> Vec<Box<dyn SecurityRuleTrait + Send + Sync>> {
    vec![
        Box::new(PublicSecurityGroupRule),
        Box::new(UnrestrictedEgressRule),
        Box::new(MissingNACLRule),
        Box::new(OverlappingCIDRRule),
        Box::new(MissingFlowLogsRule),
        Box::new(PublicLBWithSensitiveBackendRule),
        Box::new(MissingWAFRule),
        Box::new(InsecureProtocolRule),
        Box::new(DNSMisconfigurationRule),
        Box::new(MissingSegmentationRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_public_security_group_rule() {
        let rule = PublicSecurityGroupRule;
        let resource = CloudResource {
            id: "sg-test".to_string(),
            name: "test-sg".to_string(),
            resource_type: ResourceType::SecurityGroup,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "ingress_rules": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_block": "0.0.0.0/0",
                        "protocol": "tcp"
                    }
                ],
                "egress_rules": []
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
