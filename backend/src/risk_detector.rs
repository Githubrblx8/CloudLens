//! Risk Detection module for identifying security vulnerabilities in cloud infrastructure

use uuid::Uuid;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use crate::models::*;
use crate::graph::ResourceGraph;

/// Main risk detector engine
pub struct RiskDetector {
    rules: Vec<Box<dyn RiskRule>>,
}

impl RiskDetector {
    /// Create a new risk detector with default rules
    pub fn new() -> Self {
        let mut detector = Self {
            rules: Vec::new(),
        };
        
        // Register default rules
        detector.register_default_rules();
        
        detector
    }

    /// Register all default risk detection rules
    fn register_default_rules(&mut self) {
        self.add_rule(Box::new(PublicDatabaseRule));
        self.add_rule(Box::new(OverlyPermissiveIAMRule));
        self.add_rule(Box::new(UnencryptedStorageRule));
        self.add_rule(Box::new(PublicS3BucketRule));
        self.add_rule(Box::new(WildcardResourceRule));
        self.add_rule(Box::new(MissingSecurityGroupRule));
        self.add_rule(Box::new(AdminPrivilegeEscalationRule));
        self.add_rule(Box::new(CrossAccountTrustRule));
        self.add_rule(Box::new(HardcodedSecretsRule));
    }

    /// Add a custom risk detection rule
    pub fn add_rule(&mut self, rule: Box<dyn RiskRule>) {
        self.rules.push(rule);
    }

    /// Analyze a resource graph and detect risks
    pub fn analyze(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        for rule in &self.rules {
            let mut rule_risks = rule.evaluate(graph);
            risks.append(&mut rule_risks);
        }

        // Sort by severity (most critical first)
        risks.sort_by(|a, b| b.severity.cmp(&a.severity));

        risks
    }

    /// Analyze a specific resource for risks
    pub fn analyze_resource(&self, graph: &ResourceGraph, resource_id: &ResourceId) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        for rule in &self.rules {
            if let Some(resource) = graph.get_resource(resource_id) {
                let mut rule_risks = rule.evaluate_resource(graph, resource);
                risks.append(&mut rule_risks);
            }
        }

        risks
    }
}

impl Default for RiskDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for implementing risk detection rules
pub trait RiskRule: Send + Sync {
    /// Get the rule name
    fn name(&self) -> &'static str;
    
    /// Get the rule description
    fn description(&self) -> &'static str;
    
    /// Evaluate the rule against the entire graph
    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk>;
    
    /// Evaluate the rule against a specific resource (optional override)
    fn evaluate_resource(&self, _graph: &ResourceGraph, _resource: &CloudResource) -> Vec<SecurityRisk> {
        Vec::new()
    }
}

/// Rule: Detect publicly exposed databases
struct PublicDatabaseRule;

impl RiskRule for PublicDatabaseRule {
    fn name(&self) -> &'static str {
        "PUBLIC_DATABASE"
    }

    fn description(&self) -> &'static str {
        "Detects databases that are publicly accessible"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        let db_types = [
            ResourceType::Database,
            ResourceType::Custom("RDS".to_string()),
            ResourceType::Custom("DynamoDB".to_string()),
        ];

        for db_type in &db_types {
            for resource in graph.get_resources_by_type(db_type) {
                if resource.is_public {
                    risks.push(SecurityRisk {
                        id: Uuid::new_v4(),
                        title: format!("Publicly Accessible Database: {}", resource.name),
                        description: format!(
                            "The database '{}' ({}) is publicly accessible. This could allow unauthorized access to sensitive data.",
                            resource.name, resource.id
                        ),
                        severity: RiskSeverity::Critical,
                        category: RiskCategory::ExposedResource,
                        affected_resources: vec![resource.id.clone()],
                        recommendation: "Restrict database access to private networks only. Use VPC endpoints, security groups, or private link to control access.".to_string(),
                        cwe_id: Some("CWE-284".to_string()),
                        mitre_attack_id: Some("T1190".to_string()),
                        detected_at: Utc::now(),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        risks
    }
}

/// Rule: Detect overly permissive IAM policies
struct OverlyPermissiveIAMRule;

impl RiskRule for OverlyPermissiveIAMRule {
    fn name(&self) -> &'static str {
        "OVERLY_PERMISSIVE_IAM"
    }

    fn description(&self) -> &'static str {
        "Detects IAM policies with excessive permissions"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        let iam_resources = graph.get_resources_by_type(&ResourceType::Policy);
        
        for policy in iam_resources {
            if let Some(actions) = policy.metadata.get("actions") {
                if let Some(action_array) = actions.as_array() {
                    let has_wildcard = action_array.iter().any(|a| {
                        if let Some(s) = a.as_str() {
                            s == "*" || s.ends_with(":*")
                        } else {
                            false
                        }
                    });

                    if has_wildcard {
                        risks.push(SecurityRisk {
                            id: Uuid::new_v4(),
                            title: format!("Overly Permissive IAM Policy: {}", policy.name),
                            description: format!(
                                "The IAM policy '{}' grants wildcard (*) permissions which violates the principle of least privilege.",
                                policy.name
                            ),
                            severity: RiskSeverity::High,
                            category: RiskCategory::ExcessivePermissions,
                            affected_resources: vec![policy.id.clone()],
                            recommendation: "Replace wildcard permissions with specific actions required for the use case. Implement least privilege access.".to_string(),
                            cwe_id: Some("CWE-269".to_string()),
                            mitre_attack_id: Some("T1078".to_string()),
                            detected_at: Utc::now(),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }

        risks
    }
}

/// Rule: Detect unencrypted storage
struct UnencryptedStorageRule;

impl RiskRule for UnencryptedStorageRule {
    fn name(&self) -> &'static str {
        "UNENCRYPTED_STORAGE"
    }

    fn description(&self) -> &'static str {
        "Detects storage resources without encryption enabled"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        for resource in graph.get_unencrypted_resources() {
            match resource.resource_type {
                ResourceType::Bucket | ResourceType::Database | ResourceType::Disk => {
                    risks.push(SecurityRisk {
                        id: Uuid::new_v4(),
                        title: format!("Unencrypted Storage: {}", resource.name),
                        description: format!(
                            "The storage resource '{}' ({}) does not have encryption enabled. Data at rest may be exposed.",
                            resource.name, resource.resource_type
                        ),
                        severity: RiskSeverity::High,
                        category: RiskCategory::MissingEncryption,
                        affected_resources: vec![resource.id.clone()],
                        recommendation: "Enable encryption at rest using cloud provider managed keys (CMK) or customer-managed keys (KMS).".to_string(),
                        cwe_id: Some("CWE-311".to_string()),
                        mitre_attack_id: Some("T1565".to_string()),
                        detected_at: Utc::now(),
                        metadata: HashMap::new(),
                    });
                }
                _ => {}
            }
        }

        risks
    }
}

/// Rule: Detect public S3 buckets
struct PublicS3BucketRule;

impl RiskRule for PublicS3BucketRule {
    fn name(&self) -> &'static str {
        "PUBLIC_S3_BUCKET"
    }

    fn description(&self) -> &'static str {
        "Detects S3 buckets with public access"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        for bucket in graph.get_resources_by_type(&ResourceType::Bucket) {
            if bucket.provider == CloudProvider::AWS && bucket.is_public {
                let block_public_access = bucket.metadata
                    .get("block_public_access")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !block_public_access {
                    risks.push(SecurityRisk {
                        id: Uuid::new_v4(),
                        title: format!("Public S3 Bucket: {}", bucket.name),
                        description: format!(
                            "The S3 bucket '{}' is publicly accessible and does not block public access. This could lead to data leakage.",
                            bucket.name
                        ),
                        severity: RiskSeverity::Critical,
                        category: RiskCategory::ExposedResource,
                        affected_resources: vec![bucket.id.clone()],
                        recommendation: "Enable 'Block Public Access' settings on the S3 bucket. Review and restrict bucket policies.".to_string(),
                        cwe_id: Some("CWE-284".to_string()),
                        mitre_attack_id: Some("T1530".to_string()),
                        detected_at: Utc::now(),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        risks
    }
}

/// Rule: Detect wildcard resource specifications
struct WildcardResourceRule;

impl RiskRule for WildcardResourceRule {
    fn name(&self) -> &'static str {
        "WILDCARD_RESOURCE"
    }

    fn description(&self) -> &'static str {
        "Detects IAM policies with wildcard (*) resource specifications"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        let iam_resources = graph.get_resources_by_type(&ResourceType::Policy);
        
        for policy in iam_resources {
            if let Some(resources) = policy.metadata.get("resources") {
                if let Some(resource_array) = resources.as_array() {
                    let has_wildcard = resource_array.iter().any(|r| {
                        if let Some(s) = r.as_str() {
                            s == "*"
                        } else {
                            false
                        }
                    });

                    if has_wildcard {
                        risks.push(SecurityRisk {
                            id: Uuid::new_v4(),
                            title: format!("Wildcard Resource in Policy: {}", policy.name),
                            description: format!(
                                "The IAM policy '{}' uses wildcard (*) for resources, allowing actions on all resources.",
                                policy.name
                            ),
                            severity: RiskSeverity::Medium,
                            category: RiskCategory::ExcessivePermissions,
                            affected_resources: vec![policy.id.clone()],
                            recommendation: "Specify explicit resource ARNs instead of using wildcards to limit the scope of permissions.".to_string(),
                            cwe_id: Some("CWE-269".to_string()),
                            mitre_attack_id: None,
                            detected_at: Utc::now(),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }

        risks
    }
}

/// Rule: Detect missing security groups
struct MissingSecurityGroupRule;

impl RiskRule for MissingSecurityGroupRule {
    fn name(&self) -> &'static str {
        "MISSING_SECURITY_GROUP"
    }

    fn description(&self) -> &'static str {
        "Detects compute resources without associated security groups"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        let compute_types = [ResourceType::VM, ResourceType::Container];
        
        for compute_type in &compute_types {
            for resource in graph.get_resources_by_type(compute_type) {
                let has_security_group = graph.get_connected_resources(&resource.id)
                    .iter()
                    .any(|(_, rel)| rel.relationship_type == RelationshipType::Protects);

                if !has_security_group {
                    risks.push(SecurityRisk {
                        id: Uuid::new_v4(),
                        title: format!("Missing Security Group: {}", resource.name),
                        description: format!(
                            "The compute resource '{}' has no associated security group. All traffic may be allowed.",
                            resource.name
                        ),
                        severity: RiskSeverity::High,
                        category: RiskCategory::NetworkMisconfiguration,
                        affected_resources: vec![resource.id.clone()],
                        recommendation: "Attach a security group with restrictive inbound and outbound rules.".to_string(),
                        cwe_id: Some("CWE-284".to_string()),
                        mitre_attack_id: Some("T1190".to_string()),
                        detected_at: Utc::now(),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        risks
    }
}

/// Rule: Detect admin privilege escalation paths
struct AdminPrivilegeEscalationRule;

impl RiskRule for AdminPrivilegeEscalationRule {
    fn name(&self) -> &'static str {
        "ADMIN_PRIVILEGE_ESCALATION"
    }

    fn description(&self) -> &'static str {
        "Detects potential privilege escalation paths to admin roles"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        // Find admin roles
        let admin_roles: Vec<_> = graph.get_resources_by_type(&ResourceType::Role)
            .into_iter()
            .filter(|role| {
                role.name.to_lowercase().contains("admin") ||
                role.metadata.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false)
            })
            .collect();

        for admin_role in admin_roles {
            // Check if any non-admin entity can assume this role
            let connected = graph.get_connected_resources(&admin_role.id);
            
            for (source_resource, relationship) in connected {
                if relationship.relationship_type == RelationshipType::AssumesRole {
                    if !source_resource.name.to_lowercase().contains("admin") {
                        risks.push(SecurityRisk {
                            id: Uuid::new_v4(),
                            title: format!("Privilege Escalation Path to Admin"),
                            description: format!(
                                "The resource '{}' can assume the admin role '{}', creating a privilege escalation path.",
                                source_resource.name, admin_role.name
                            ),
                            severity: RiskSeverity::Critical,
                            category: RiskCategory::IdentityRisk,
                            affected_resources: vec![source_resource.id.clone(), admin_role.id.clone()],
                            recommendation: "Restrict role assumption to specific, trusted identities. Implement MFA requirements for role assumption.".to_string(),
                            cwe_id: Some("CWE-269".to_string()),
                            mitre_attack_id: Some("T1078".to_string()),
                            detected_at: Utc::now(),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }

        risks
    }
}

/// Rule: Detect risky cross-account trust relationships
struct CrossAccountTrustRule;

impl RiskRule for CrossAccountTrustRule {
    fn name(&self) -> &'static str {
        "CROSS_ACCOUNT_TRUST"
    }

    fn description(&self) -> &'static str {
        "Detects potentially risky cross-account trust relationships"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        let roles = graph.get_resources_by_type(&ResourceType::Role);
        
        for role in roles {
            if let Some(trusted_accounts) = role.metadata.get("trusted_accounts") {
                if let Some(accounts) = trusted_accounts.as_array() {
                    // Check for wildcard account trust
                    for account in accounts {
                        if let Some(acc_str) = account.as_str() {
                            if acc_str == "*" || acc_str.contains("*") {
                                risks.push(SecurityRisk {
                                    id: Uuid::new_v4(),
                                    title: format!("Risky Cross-Account Trust: {}", role.name),
                                    description: format!(
                                        "The role '{}' trusts external account '{}', which could allow unauthorized access.",
                                        role.name, acc_str
                                    ),
                                    severity: RiskSeverity::High,
                                    category: RiskCategory::IdentityRisk,
                                    affected_resources: vec![role.id.clone()],
                                    recommendation: "Review and restrict cross-account trust relationships to known, trusted accounts only.".to_string(),
                                    cwe_id: Some("CWE-284".to_string()),
                                    mitre_attack_id: Some("T1078".to_string()),
                                    detected_at: Utc::now(),
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        risks
    }
}

/// Rule: Detect hardcoded secrets in metadata
struct HardcodedSecretsRule;

impl RiskRule for HardcodedSecretsRule {
    fn name(&self) -> &'static str {
        "HARDCODED_SECRETS"
    }

    fn description(&self) -> &'static str {
        "Detects potential hardcoded secrets in resource metadata"
    }

    fn evaluate(&self, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();
        
        let secret_patterns = ["password", "secret", "api_key", "apikey", "token", "credential", "private_key"];
        
        for node_idx in graph.to_export_format().nodes.iter() {
            // This is a simplified check - in production, you'd scan actual metadata
            let resource_name_lower = node_idx.name.to_lowercase();
            
            for pattern in &secret_patterns {
                if resource_name_lower.contains(pattern) {
                    if node_idx.name.to_uppercase() == node_idx.name || 
                       node_idx.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        risks.push(SecurityRisk {
                            id: Uuid::new_v4(),
                            title: format!("Potential Hardcoded Secret: {}", node_idx.name),
                            description: format!(
                                "The resource name '{}' suggests it may contain hardcoded secrets or credentials.",
                                node_idx.name
                            ),
                            severity: RiskSeverity::Medium,
                            category: RiskCategory::SecretExposure,
                            affected_resources: vec![node_idx.id.clone()],
                            recommendation: "Use a secrets manager service (AWS Secrets Manager, Azure Key Vault, etc.) instead of hardcoding credentials.".to_string(),
                            cwe_id: Some("CWE-798".to_string()),
                            mitre_attack_id: Some("T1552".to_string()),
                            detected_at: Utc::now(),
                            metadata: HashMap::new(),
                        });
                        break;
                    }
                }
            }
        }

        risks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_graph() -> ResourceGraph {
        let mut graph = ResourceGraph::new();
        
        // Add a public database
        let mut db = CloudResource {
            id: "db-1".to_string(),
            arn: "arn:aws:rds:us-east-1:123456789012:db:testdb".to_string(),
            name: "TestDatabase".to_string(),
            resource_type: ResourceType::Database,
            provider: CloudProvider::AWS,
            region: Some("us-east-1".to_string()),
            metadata: HashMap::new(),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
            is_public: true,
            encryption_status: EncryptionStatus::Disabled,
        };
        
        graph.add_resource(db).unwrap();
        
        graph
    }

    #[test]
    fn test_risk_detector_creation() {
        let detector = RiskDetector::new();
        assert!(!detector.rules.is_empty());
    }

    #[test]
    fn test_detect_public_database() {
        let graph = create_test_graph();
        let detector = RiskDetector::new();
        
        let risks = detector.analyze(&graph);
        
        let public_db_risk = risks.iter().find(|r| r.category == RiskCategory::ExposedResource);
        assert!(public_db_risk.is_some());
        assert_eq!(public_db_risk.unwrap().severity, RiskSeverity::Critical);
    }
}
