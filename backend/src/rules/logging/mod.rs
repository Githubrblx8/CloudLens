// CloudLens - Logging & Monitoring Security Rules Module
// Comprehensive logging, monitoring, and observability security rules
// Part of the 40K lines security rules implementation

use crate::models::{SecurityRule, SecurityRisk, RiskSeverity, RiskCategory, CloudResource, ResourceType};
use crate::traits::SecurityRuleTrait;
use async_trait::async_trait;
use std::collections::HashMap;

/// Rule: CloudTrail/Activity Logs Disabled
pub struct CloudTrailDisabledRule;

#[async_trait]
impl SecurityRuleTrait for CloudTrailDisabledRule {
    fn id(&self) -> &'static str { "LOG-001" }
    fn name(&self) -> &'static str { "CloudTrail/Activity Logs Disabled" }
    fn description(&self) -> &'static str { 
        "Cloud audit logging is not enabled, preventing forensic analysis" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Critical }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::CloudTrail 
            && resource.resource_type != ResourceType::AuditLog
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let enabled = config.get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Audit logging {} is disabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable cloud audit logging with multi-region trails".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Log Retention Too Short
pub struct LogRetentionTooShortRule;

#[async_trait]
impl SecurityRuleTrait for LogRetentionTooShortRule {
    fn id(&self) -> &'static str { "LOG-002" }
    fn name(&self) -> &'static str { "Log Retention Period Too Short" }
    fn description(&self) -> &'static str { 
        "Log retention period is insufficient for compliance and forensics" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::Compliance }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::LogGroup 
            && resource.resource_type != ResourceType::StorageBucket
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let retention_days = config.get("retention_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        // Most compliance frameworks require at least 90 days, some require 365+
        if retention_days > 0 && retention_days < 90 {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Log retention ({}) is below recommended 90 days",
                    retention_days
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Increase log retention to at least 90 days for compliance".to_string(),
                metadata: HashMap::from([
                    ("retention_days".to_string(), retention_days.to_string()),
                ]),
            });
        }
        
        None
    }
}

/// Rule: Logs Not Encrypted
pub struct LogsNotEncryptedRule;

#[async_trait]
impl SecurityRuleTrait for LogsNotEncryptedRule {
    fn id(&self) -> &'static str { "LOG-003" }
    fn name(&self) -> &'static str { "Logs Not Encrypted" }
    fn description(&self) -> &'static str { 
        "Log data is stored without encryption at rest" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::DataProtection }
    fn cwe_id(&self) -> &'static str { "CWE-311" }
    fn mitre_id(&self) -> &'static str { "T1565" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::LogGroup 
            && resource.resource_type != ResourceType::StorageBucket
        {
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
                    "Log storage {} is not encrypted",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable encryption at rest for all log storage".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: No Alarm for Root Account Usage
pub struct RootAccountNoAlarmRule;

#[async_trait]
impl SecurityRuleTrait for RootAccountNoAlarmRule {
    fn id(&self) -> &'static str { "LOG-004" }
    fn name(&self) -> &'static str { "No Alarm for Root Account Usage" }
    fn description(&self) -> &'static str { 
        "No alerting configured for root/admin account usage" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-284" }
    fn mitre_id(&self) -> &'static str { "T1078" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::Alarm 
            && resource.resource_type != ResourceType::Monitor
        {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let monitors_root = config.get("monitors_root_usage")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let alarm_enabled = config.get("alarm_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !monitors_root && alarm_enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Alarm {} does not monitor root account usage",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Create alerts for any root/admin account activity".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: VPC Flow Logs Disabled
pub struct VPCFlowLogsDisabledRule;

#[async_trait]
impl SecurityRuleTrait for VPCFlowLogsDisabledRule {
    fn id(&self) -> &'static str { "LOG-005" }
    fn name(&self) -> &'static str { "VPC Flow Logs Disabled" }
    fn description(&self) -> &'static str { 
        "Network flow logs are not enabled for traffic analysis" 
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
        let flow_logs_enabled = config.get("flow_logs_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !flow_logs_enabled {
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
                remediation: "Enable VPC flow logs for network forensics".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: No Centralized Logging
pub struct NoCentralizedLoggingRule;

#[async_trait]
impl SecurityRuleTrait for NoCentralizedLoggingRule {
    fn id(&self) -> &'static str | 'static str { "LOG-006" }
    fn name(&self) -> &'static str { "No Centralized Logging" }
    fn description(&self) -> &'static str { 
        "Logs are not aggregated to a centralized secure location" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        let config = resource.configuration.as_object()?;
        let has_centralized_logging = config.get("centralized_logging")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let log_destination = config.get("log_destination")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        if !has_centralized_logging && log_destination.is_empty() {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Resource {} does not send logs to centralized location",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Configure centralized logging with SIEM integration".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Metric Filter for Unauthorized API Calls Missing
pub struct MissingUnauthorizedAPIMetricRule;

#[async_trait]
impl SecurityRuleTrait for MissingUnauthorizedAPIMetricRule {
    fn id(&self) -> &'static str { "LOG-007" }
    fn name(&self) -> &'static str { "Missing Metric Filter for Unauthorized API Calls" }
    fn description(&self) -> &'static str { 
        "No metric filter configured to detect unauthorized API calls" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::MetricFilter {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let filters_unauthorized = config.get("filters_unauthorized_calls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !filters_unauthorized {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Metric filter {} does not detect unauthorized API calls",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Create metric filters for AccessDenied and UnauthorizedOperation errors".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: S3 Bucket Access Logging Disabled
pub struct S3AccessLoggingDisabledRule;

#[async_trait]
impl SecurityRuleTrait for S3AccessLoggingDisabledRule {
    fn id(&self) -> &'static str { "LOG-008" }
    fn name(&self) -> &'static str { "S3 Bucket Access Logging Disabled" }
    fn description(&self) -> &'static str { 
        "S3 bucket does not have access logging enabled" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Medium }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::StorageBucket {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let access_logging_enabled = config.get("access_logging_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !access_logging_enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "S3 bucket {} does not have access logging enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable S3 server access logging for audit trail".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: DNS Query Logging Disabled
pub struct DNSQueryLoggingDisabledRule;

#[async_trait]
impl SecurityRuleTrait for DNSQueryLoggingDisabledRule {
    fn id(&self) -> &'static str { "LOG-009" }
    fn name(&self) -> &'static str { "DNS Query Logging Disabled" }
    fn description(&self) -> &'static str { 
        "DNS query logging is not enabled for threat detection" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::Low }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1071.004" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::DNSZone {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let query_logging_enabled = config.get("query_logging_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        if !query_logging_enabled {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "DNS zone {} does not have query logging enabled",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable DNS query logging for threat hunting".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

/// Rule: Kubernetes Audit Logging Disabled
pub struct K8sAuditLoggingDisabledRule;

#[async_trait]
impl SecurityRuleTrait for K8sAuditLoggingDisabledRule {
    fn id(&self) -> &'static str { "LOG-010" }
    fn name(&self) -> &'static str { "Kubernetes Audit Logging Disabled" }
    fn description(&self) -> &'static str { 
        "Kubernetes cluster does not have audit logging enabled" 
    }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    fn category(&self) -> RiskCategory { RiskCategory::LoggingMonitoring }
    fn cwe_id(&self) -> &'static str { "CWE-778" }
    fn mitre_id(&self) -> &'static str { "T1070" }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        if resource.resource_type != ResourceType::KubernetesCluster {
            return None;
        }

        let config = resource.configuration.as_object()?;
        let audit_logging_enabled = config.get("audit_logging_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let audit_log_path = config.get("audit_log_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        if !audit_logging_enabled || audit_log_path.is_empty() {
            return Some(SecurityRisk {
                id: format!("{}-{}", self.id(), resource.id),
                rule_id: self.id().to_string(),
                resource_id: resource.id.clone(),
                resource_type: resource.resource_type.clone(),
                severity: self.severity(),
                category: self.category(),
                title: self.name().to_string(),
                description: format!(
                    "Kubernetes cluster {} lacks audit logging configuration",
                    resource.name
                ),
                cwe_id: self.cwe_id().to_string(),
                mitre_id: self.mitre_id().to_string(),
                remediation: "Enable Kubernetes audit logging with proper policy".to_string(),
                metadata: HashMap::new(),
            });
        }
        
        None
    }
}

// Export all logging security rules
pub fn get_logging_rules() -> Vec<Box<dyn SecurityRuleTrait + Send + Sync>> {
    vec![
        Box::new(CloudTrailDisabledRule),
        Box::new(LogRetentionTooShortRule),
        Box::new(LogsNotEncryptedRule),
        Box::new(RootAccountNoAlarmRule),
        Box::new(VPCFlowLogsDisabledRule),
        Box::new(NoCentralizedLoggingRule),
        Box::new(MissingUnauthorizedAPIMetricRule),
        Box::new(S3AccessLoggingDisabledRule),
        Box::new(DNSQueryLoggingDisabledRule),
        Box::new(K8sAuditLoggingDisabledRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_cloudtrail_disabled_rule() {
        let rule = CloudTrailDisabledRule;
        let resource = CloudResource {
            id: "trail-test".to_string(),
            name: "disabled-trail".to_string(),
            resource_type: ResourceType::CloudTrail,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "enabled": false,
                "multi_region": false
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
    async fn test_log_retention_rule() {
        let rule = LogRetentionTooShortRule;
        let resource = CloudResource {
            id: "loggroup-test".to_string(),
            name: "short-retention".to_string(),
            resource_type: ResourceType::LogGroup,
            provider: crate::models::CloudProvider::AWS,
            region: "us-east-1".to_string(),
            configuration: json!({
                "retention_days": 30,
                "encrypted": true
            }),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
        };

        let result = rule.evaluate(&resource).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, RiskSeverity::Medium);
    }
}
