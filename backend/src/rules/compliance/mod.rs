// CloudGhidra - Compliance Security Rules Module
// Comprehensive compliance and regulatory security rules
// Part of the 40K lines security rules implementation

use crate::models::{SecurityRule, SecurityRisk, RiskSeverity, RiskCategory, CloudResource, ResourceType, ComplianceFramework};
use crate::traits::SecurityRuleTrait;
use async_trait::async_trait;
use std::collections::HashMap;

/// Rule: SOC2 Access Control Requirement
pub struct SOC2AccessControlRule;

#[async_trait]
impl SecurityRuleTrait for SOC2AccessControlRule {
    fn id(&self) -> &'static str { "COMP-SOC2-001" }
    fn name(&self) -> &'static str { "SOC2 Access Control Requirement" }
    fn description(&self) -> &'static str { 
        "Resources must have proper access controls per SOC2 CC6.1" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let has_access_control = config.get("access_control_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let public_access = config.get("public_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !has_access_control || public_access {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} does not meet SOC2 access control requirements",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Implement proper access controls and remove public access".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "SOC2".to_string()),
                    ("control".to_string(), "CC6.1".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: PCI-DSS Encryption Requirement
pub struct PCIDSSEncryptionRule;

#[async_trait]
impl SecurityRuleTrait for PCIDSSEncryptionRule {
    fn id(&self) -> &'static str { "COMP-PCI-001" }
    fn name(&self) -> &'static str { "PCI-DSS Encryption Requirement" }
    fn description(&self) -> &'static str { 
        "Cardholder data must be encrypted per PCI-DSS requirement 3.4" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-311" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Database 
            && resource.resource_type != ResourceType::StorageBucket
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let stores_cardholder_data = config.get("stores_cardholder_data")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let encrypted = config.get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if stores_cardholder_data && !encrypted {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} storing cardholder data is not encrypted (PCI-DSS 3.4)",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption for all cardholder data storage".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "PCI-DSS".to_string()),
                    ("requirement".to_string(), "3.4".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: HIPAA PHI Protection
pub struct HIPAAPHIProtectionRule;

#[async_trait]
impl SecurityRuleTrait for HIPAAPHIProtectionRule {
    fn id(&self) -> &'static str { "COMP-HIPAA-001" }
    fn name(&self) -> &'static str { "HIPAA PHI Protection Requirement" }
    fn description(&self) -> &'static str { 
        "PHI data must have proper safeguards per HIPAA Security Rule" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let contains_phi = config.get("contains_phi")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let encrypted = config.get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let access_logged = config.get("access_logged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if contains_phi && (!encrypted || !access_logged) {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} containing PHI lacks required HIPAA safeguards",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption and audit logging for PHI resources".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "HIPAA".to_string()),
                    ("rule".to_string(), "Security Rule".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: GDPR Data Residency
pub struct GDPRDataResidencyRule;

#[async_trait]
impl SecurityRuleTrait for GDPRDataResidencyRule {
    fn id(&self) -> &'static str { "COMP-GDPR-001" }
    fn name(&self) -> &'static str { "GDPR Data Residency Requirement" }
    fn description(&self) -> &'static str { 
        "EU personal data must comply with GDPR data transfer restrictions" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let contains_eu_personal_data = config.get("contains_eu_personal_data")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let region = resource.region.to_lowercase();
        let eu_regions = ["eu-", "europe", "frankfurt", "ireland", "paris", "london"];
        let in_eu_region = eu_regions.iter().any(|r| region.contains(r));
        
        let has_transfer_safeguards = config.get("transfer_safeguards")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if contains_eu_personal_data && !in_eu_region && !has_transfer_safeguards {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} with EU data is outside EU without transfer safeguards",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Move data to EU region or implement Standard Contractual Clauses".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "GDPR".to_string()),
                    ("article".to_string(), "44-50".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: ISO27001 Logging Requirement
pub struct ISO27001LoggingRule;

#[async_trait]
impl SecurityRuleTrait for ISO27001LoggingRule {
    fn id(&self) -> &'static str { "COMP-ISO-001" }
    fn name(&self) -> &'static str { "ISO27001 Logging Requirement" }
    fn description(&self) -> &'static str { 
        "Systems must maintain audit logs per ISO27001 A.12.4" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let logging_enabled = config.get("logging_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let log_retention_days = config.get("log_retention_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        if !logging_enabled || log_retention_days < 90 {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} does not meet ISO27001 logging requirements",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable comprehensive logging with minimum 90-day retention".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "ISO27001".to_string()),
                    ("control".to_string(), "A.12.4".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: NIST Access Control
pub struct NISTAccessControlRule;

#[async_trait]
impl SecurityRuleTrait for NISTAccessControlRule {
    fn id(&self) -> &'static str { "COMP-NIST-001" }
    fn name(&self) -> &'static str { "NIST Access Control Requirement" }
    fn description(&self) -> &'static str { 
        "Systems must enforce least privilege per NIST SP 800-53 AC-6" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-269" }
    fn mitre_id(&self) -> &'static str { "T1078" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let uses_least_privilege = config.get("uses_least_privilege")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_admin_account = config.get("has_admin_account")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let mfa_enabled = config.get("mfa_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !uses_least_privilege || (has_admin_account && !mfa_enabled) {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} does not meet NIST access control requirements",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Implement least privilege and require MFA for admin accounts".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "NIST".to_string()),
                    ("control".to_string(), "AC-6".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: CIS Benchmark Compliance
pub struct CISBenchmarkRule;

#[async_trait]
impl SecurityRuleTrait for CISBenchmarkRule {
    fn id(&self) -> &'static str { "COMP-CIS-001" }
    fn name(&self) -> &'static str { "CIS Benchmark Compliance" }
    fn description(&self) -> &'static str { 
        "Resource configuration deviates from CIS security benchmarks" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1190" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let cis_compliant = config.get("cis_compliant")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let cis_level = config.get("cis_level")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        let failed_checks = config.get("cis_failed_checks")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        if !cis_compliant || failed_checks > 0 {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} fails {} CIS benchmark checks",
                    resource.name, failed_checks
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Remediate failed CIS benchmark checks to improve security posture".to_string(),
                metadata: HashMap::from([
                    ("framework".to_string(), "CIS".to_string()),
                    ("level".to_string(), cis_level.to_string()),
                    ("failed_checks".to_string(), failed_checks.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Multi-Factor Authentication Required
pub struct MFARequiredRule;

#[async_trait]
impl SecurityRuleTrait for MFARequiredRule {
    fn id(&self) -> &'static str { "COMP-MFA-001" }
    fn name(&self) -> &'static str { "Multi-Factor Authentication Required" }
    fn description(&self) -> &'static str { 
        "Administrative access requires MFA per multiple compliance frameworks" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-306" }
    fn mitre_id(&self) -> &'static str { "T1078" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::IAMUser 
            && resource.resource_type != ResourceType::IAMRole
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let is_admin = config.get("is_admin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let mfa_enabled = config.get("mfa_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if is_admin && !mfa_enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Admin account {} does not have MFA enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable MFA for all administrative accounts".to_string(),
                metadata: HashMap::from([
                    ("frameworks".to_string(), "SOC2,PCI-DSS,HIPAA,NIST".to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Data Classification Missing
pub struct DataClassificationMissingRule;

#[async_trait]
impl SecurityRuleTrait for DataClassificationMissingRule {
    fn id(&self) -> &'static str | 'static str { "COMP-CLASS-001" }
    fn name(&self) -> &'static str { "Data Classification Missing" }
    fn description(&self) -> &'static str { 
        "Resources storing sensitive data lack proper classification labels" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let contains_sensitive = config.get("contains_sensitive_data")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_classification = resource.tags.get("classification").is_some()
            || resource.tags.get("data_classification").is_some()
            || resource.tags.get("sensitivity").is_some();
        
        if contains_sensitive && !has_classification {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} with sensitive data lacks classification",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Apply data classification tags for proper handling".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

// Export all compliance security rules
pub fn get_compliance_rules() -> Vec<Box<dyn SecurityRuleTrait + Send + Sync>> {
    vec![
        Box::new(SOC2AccessControlRule),
        Box::new(PCIDSSEncryptionRule),
        Box::new(HIPAAPHIProtectionRule),
        Box::new(GDPRDataResidencyRule),
        Box::new(ISO27001LoggingRule),
        Box::new(NISTAccessControlRule),
        Box::new(CISBenchmarkRule),
        Box::new(MFARequiredRule),
        Box::new(DataClassificationMissingRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_pci_encryption_rule() {
        let rule = PCIDSSEncryptionRule;
        let resource = CloudResource {
            id: "db-pci".to_string(),
            name: "cardholder-db".to_string(),
            resource_type: ResourceType::Database,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "stores_cardholder_data": true,
                "encrypted": false
            }),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
        };

        let result = rule.evaluate(&resource).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, RiskSeverity::Critical);
    }

    #[tokio::test]
    async fn test_mfa_required_rule() {
        let rule = MFARequiredRule;
        let resource = CloudResource {
            id: "user-admin".to_string(),
            name: "admin-user".to_string(),
            resource_type: ResourceType::IAMUser,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "is_admin": true,
                "mfa_enabled": false
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
