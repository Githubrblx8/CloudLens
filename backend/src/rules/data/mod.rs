// CloudLens - Data Security Rules Module
// Comprehensive data protection and storage security rules
// Part of the 40K lines security rules implementation

use crate::models::{SecurityRule, SecurityRisk, RiskSeverity, RiskCategory, CloudResource, ResourceType};
use crate::traits::SecurityRuleTrait;
use async_trait::async_trait;
use std::collections::HashMap;

/// Rule: Unencrypted Storage Bucket
pub struct UnencryptedStorageRule;

#[async_trait]
impl SecurityRuleTrait for UnencryptedStorageRule {
    fn id(&self) -> &'static str { "DATA-001" }
    fn name(&self) -> &'static str { "Unencrypted Storage Bucket" }
    fn description(&self) -> &'static str { 
        "Storage bucket does not have server-side encryption enabled" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::DataProtection }
    fn cwe_id(&self) -> &'static str { "CWE-311" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::StorageBucket 
            && resource.resource_type != ResourceType::ObjectStorage
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let encryption_enabled = config.get("encryption_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let encryption_type = config.get("encryption_type")
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        
        if !encryption_enabled || encryption_type == "none" {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Storage bucket {} does not have encryption enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable server-side encryption with AES-256 or customer-managed keys".to_string(),
                metadata: HashMap::from([
                    ("encryption_enabled".to_string(), encryption_enabled.to_string()),
                    ("encryption_type".to_string(), encryption_type.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Public Storage Bucket
pub struct PublicStorageBucketRule;

#[async_trait]
impl SecurityRuleTrait for PublicStorageBucketRule {
    fn id(&self) -> &'static str { "DATA-002" }
    fn name(&self) -> &'static str { "Public Storage Bucket" }
    fn description(&self) -> &'static str { 
        "Storage bucket is publicly accessible without authentication" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::DataExposure }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1530" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::StorageBucket 
            && resource.resource_type != ResourceType::ObjectStorage
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let public_access = config.get("public_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let acl = config.get("acl")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        let is_public = public_access 
            || acl == "public-read" 
            || acl == "public-read-write"
            || acl == "authenticated-read";
        
        if is_public {
            let contains_sensitive = config.get("contains_sensitive_data")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            
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
                    "Storage bucket {} is publicly accessible (ACL: {})",
                    resource.name, acl
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Block all public access and implement proper IAM policies".to_string(),
                metadata: HashMap::from([
                    ("public_access".to_string(), public_access.to_string()),
                    ("acl".to_string(), acl.to_string()),
                    ("contains_sensitive".to_string(), contains_sensitive.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Missing Bucket Versioning
pub struct MissingVersioningRule;

#[async_trait]
impl SecurityRuleTrait for MissingVersioningRule {
    fn id(&self) -> &'static str { "DATA-003" }
    fn name(&self) -> &'static str { "Missing Bucket Versioning" }
    fn description(&self) -> &'static str { 
        "Storage bucket does not have versioning enabled, risking data loss from accidental deletion or ransomware" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::DataProtection }
    fn cwe_id(&self) -> &'static str { "CWE-693" }
    fn mitre_id(&self) -> &'static str { "T1486" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::StorageBucket 
            && resource.resource_type != ResourceType::ObjectStorage
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let versioning_enabled = config.get("versioning_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !versioning_enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Storage bucket {} does not have versioning enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable object versioning to protect against accidental deletion and ransomware".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Unencrypted Database
pub struct UnencryptedDatabaseRule;

#[async_trait]
impl SecurityRuleTrait for UnencryptedDatabaseRule {
    fn id(&self) -> &'static str { "DATA-004" }
    fn name(&self) -> &'static str { "Unencrypted Database" }
    fn description(&self) -> &'static str { 
        "Database instance does not have encryption at rest enabled" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::DataProtection }
    fn cwe_id(&self) -> &'static str { "CWE-311" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Database {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let encryption_enabled = config.get("storage_encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !encryption_enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Database {} does not have encryption at rest enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption at rest using AWS KMS, Azure Key Vault, or GCP CMEK".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Database Without SSL/TLS
pub struct DatabaseWithoutSSLRule;

#[async_trait]
impl SecurityRuleTrait for DatabaseWithoutSSLRule {
    fn id(&self) -> &'static str { "DATA-005" }
    fn name(&self) -> &'static str { "Database Without SSL/TLS" }
    fn description(&self) -> &'static str { 
        "Database does not enforce SSL/TLS for connections" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::Encryption }
    fn cwe_id(&self) -> &'static str { "CWE-319" }
    fn mitre_id(&self) -> &'static str { "T1040" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Database {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let ssl_required = config.get("require_ssl")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let ssl_enforced = config.get("ssl_enforced")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !ssl_required && !ssl_enforced {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Database {} does not enforce SSL/TLS connections",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enforce SSL/TLS for all database connections".to_string(),
                metadata: HashMap::from([
                    ("ssl_required".to_string(), ssl_required.to_string()),
                    ("ssl_enforced".to_string(), ssl_enforced.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Excessive Database Permissions
pub struct ExcessiveDBPermissionsRule;

#[async_trait]
impl SecurityRuleTrait for ExcessiveDBPermissionsRule {
    fn id(&self) -> &'static str { "DATA-006" }
    fn name(&self) -> &'static str { "Excessive Database Permissions" }
    fn description(&self) -> &'static str { 
        "Database user has excessive privileges beyond job requirements" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::PrivilegeEscalation }
    fn cwe_id(&self) -> &'static str { "CWE-269" }
    fn mitre_id(&self) -> &'static str { "T1078" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::DatabaseUser {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let permissions = config.get("permissions")
            .and_then(|v| v.as_array());
        
        if let Some(perms) = permissions {
            let dangerous_perms = ["SUPER", "FILE", "PROCESS", "RELOAD", "SHUTDOWN", "ALL PRIVILEGES"];
            let has_dangerous = perms.iter().any(|p| {
                let perm = p.as_str().unwrap_or("");
                dangerous_perms.iter().any(|dp| perm.contains(dp))
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
                        "Database user {} has excessive administrative privileges",
                        resource.name
                    ),
                    cwe_id: self.cwe_id().to_string(),
                    mitre_id: self.mitre_id().to_string(),
                    remediation: "Apply principle of least privilege and remove unnecessary permissions".to_string(),
                    metadata: HashMap::new(),
                });
            }
        }
        
        None
    }
}

/// Rule: Missing Data Classification
pub struct MissingDataClassificationRule;

#[async_trait]
impl SecurityRuleTrait for MissingDataClassificationRule {
    fn id(&self) -> &'static str { "DATA-007" }
    fn name(&self) -> &'static str { "Missing Data Classification" }
    fn description(&self) -> &'static str { 
        "Storage resource contains sensitive data without proper classification tags" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let sensitive_types = ["pii", "phi", "pci", "financial", "credentials"];
        
        let config = resource.configuration.as_object()?;
        let contains_sensitive = config.get("contains_sensitive_data")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_classification = resource.tags.get("data_classification").is_some()
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
                    "Resource {} contains sensitive data without classification tags",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Add data classification tags (e.g., 'confidential', 'pii', 'phi') to enable proper handling".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Missing Backup Encryption
pub struct MissingBackupEncryptionRule;

#[async_trait]
impl SecurityRuleTrait for MissingBackupEncryptionRule {
    fn id(&self) -> &'static str { "DATA-008" }
    fn name(&self) -> &'static str { "Missing Backup Encryption" }
    fn description(&self) -> &'static str { 
        "Database or storage backups are not encrypted" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::DataProtection }
    fn cwe_id(&self) -> &'static str { "CWE-311" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Database 
            && resource.resource_type != ResourceType::BackupVault
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let backup_encrypted = config.get("backup_encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let has_backups = config.get("has_backups")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if has_backups && !backup_encrypted {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Backups for {} are not encrypted",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption for all backups using customer-managed keys".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Cross-Region Data Transfer Without Encryption
pub struct CrossRegionUnencryptedRule;

#[async_trait]
impl SecurityRuleTrait for CrossRegionUnencryptedRule {
    fn id(&self) -> &'static str { "DATA-009" }
    fn name(&self) -> &'static str { "Cross-Region Data Transfer Without Encryption" }
    fn description(&self) -> &'static str { 
        "Data replication across regions does not use encryption in transit" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Encryption }
    fn cwe_id(&self) -> &'static str { "CWE-319" }
    fn mitre_id(&self) -> &'static str { "T1040" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::StorageBucket 
            && resource.resource_type != ResourceType::Database
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let cross_region_replication = config.get("cross_region_replication")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let replication_encrypted = config.get("replication_encryption")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if cross_region_replication && !replication_encrypted {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Cross-region replication for {} is not encrypted in transit",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption for cross-region data transfers".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Missing Data Retention Policy
pub struct MissingRetentionPolicyRule;

#[async_trait]
impl SecurityRuleTrait for MissingRetentionPolicyRule {
    fn id(&self) -> &'static str { "DATA-010" }
    fn name(&self) -> &'static str { "Missing Data Retention Policy" }
    fn description(&self) -> &'static str { 
        "Storage resource lacks defined data retention and deletion policies" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Low }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-693" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::StorageBucket 
            && resource.resource_type != ResourceType::Database
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let has_lifecycle_policy = config.get("lifecycle_policy")
            .and_then(|v| v.as_object())
            .is_some();
        
        let has_retention = config.get("retention_period_days")
            .and_then(|v| v.as_u64())
            .is_some();
        
        if !has_lifecycle_policy && !has_retention {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} lacks data retention and lifecycle policies",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Define lifecycle policies and retention periods compliant with regulatory requirements".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

// Export all data security rules
pub fn get_data_rules() -> Vec<Box<dyn SecurityRuleTrait + Send + Sync>> {
    vec![
        Box::new(UnencryptedStorageRule),
        Box::new(PublicStorageBucketRule),
        Box::new(MissingVersioningRule),
        Box::new(UnencryptedDatabaseRule),
        Box::new(DatabaseWithoutSSLRule),
        Box::new(ExcessiveDBPermissionsRule),
        Box::new(MissingDataClassificationRule),
        Box::new(MissingBackupEncryptionRule),
        Box::new(CrossRegionUnencryptedRule),
        Box::new(MissingRetentionPolicyRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_unencrypted_storage_rule() {
        let rule = UnencryptedStorageRule;
        let resource = CloudResource {
            id: "bucket-test".to_string(),
            name: "test-bucket".to_string(),
            resource_type: ResourceType::StorageBucket,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "encryption_enabled": false,
                "encryption_type": "none",
                "public_access": false,
                "versioning_enabled": false
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
    async fn test_public_bucket_rule() {
        let rule = PublicStorageBucketRule;
        let resource = CloudResource {
            id: "bucket-public".to_string(),
            name: "public-bucket".to_string(),
            resource_type: ResourceType::StorageBucket,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "encryption_enabled": true,
                "encryption_type": "AES256",
                "public_access": true,
                "acl": "public-read",
                "contains_sensitive_data": true
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
