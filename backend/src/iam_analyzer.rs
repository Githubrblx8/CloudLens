//! IAM Analyzer module for analyzing identity and access management configurations

use std::collections::{HashMap, HashSet};
use crate::models::*;
use crate::graph::ResourceGraph;

/// Main IAM analyzer engine
pub struct IAMAnalyzer {
    policy_cache: HashMap<String, IAMPolicy>,
}

impl IAMAnalyzer {
    /// Create a new IAM analyzer
    pub fn new() -> Self {
        Self {
            policy_cache: HashMap::new(),
        }
    }

    /// Analyze IAM policies in the resource graph
    pub fn analyze_policies(&mut self, graph: &ResourceGraph) -> IAMAnalysisResult {
        let mut result = IAMAnalysisResult::default();
        
        // Extract and parse IAM policies
        let policies = self.extract_policies(graph);
        
        // Analyze each policy
        for policy in &policies {
            let findings = self.analyze_single_policy(policy);
            result.findings.extend(findings);
        }
        
        // Find privilege escalation paths
        result.escalation_paths = self.find_privilege_escalation_paths(graph);
        
        // Calculate effective permissions
        result.effective_permissions = self.calculate_effective_permissions(graph);
        
        // Identify overly permissive identities
        result.overly_permissive = self.identify_overly_permissive_identities(graph);
        
        result
    }

    /// Extract IAM policies from the resource graph
    fn extract_policies(&self, graph: &ResourceGraph) -> Vec<IAMPolicy> {
        let mut policies = Vec::new();
        
        let policy_resources = graph.get_resources_by_type(&ResourceType::Policy);
        
        for policy_resource in policy_resources {
            if let Some(policy_doc) = policy_resource.metadata.get("policy_document") {
                if let Ok(policy) = serde_json::from_value::<IAMPolicy>(policy_doc.clone()) {
                    policies.push(policy);
                }
            }
        }
        
        policies
    }

    /// Analyze a single IAM policy
    fn analyze_single_policy(&self, policy: &IAMPolicy) -> Vec<IAMFinding> {
        let mut findings = Vec::new();
        
        for statement in &policy.statements {
            if statement.effect == IAMEffect::Allow {
                // Check for wildcard actions
                for action in &statement.actions {
                    if action == "*" || action.ends_with(":*") {
                        findings.push(IAMFinding {
                            policy_name: policy.name.clone(),
                            finding_type: IAMFindingType::WildcardAction,
                            severity: RiskSeverity::High,
                            description: format!("Policy allows wildcard action: {}", action),
                            recommendation: "Replace wildcard actions with specific required actions".to_string(),
                        });
                    }
                }
                
                // Check for wildcard resources
                for resource in &statement.resources {
                    if resource == "*" {
                        findings.push(IAMFinding {
                            policy_name: policy.name.clone(),
                            finding_type: IAMFindingType::WildcardResource,
                            severity: RiskSeverity::Medium,
                            description: "Policy allows actions on all resources (*)".to_string(),
                            recommendation: "Specify explicit resource ARNs instead of wildcards".to_string(),
                        });
                    }
                }
                
                // Check for dangerous permission combinations
                let dangerous_perms = self.check_dangerous_permissions(&statement.actions);
                if !dangerous_perms.is_empty() {
                    findings.push(IAMFinding {
                        policy_name: policy.name.clone(),
                        finding_type: IAMFindingType::DangerousPermissions,
                        severity: RiskSeverity::Critical,
                        description: format!("Policy contains dangerous permissions: {:?}", dangerous_perms),
                        recommendation: "Review and restrict dangerous permissions".to_string(),
                    });
                }
            }
        }
        
        findings
    }

    /// Check for dangerous permission combinations
    fn check_dangerous_permissions(&self, actions: &[String]) -> Vec<String> {
        let dangerous_actions = [
            "iam:*",
            "iam:CreateUser",
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "sts:AssumeRole",
            "lambda:CreateFunction",
            "lambda:AddPermission",
            "ec2:RunInstances",
            "cloudformation:CreateStack",
            "glue:UpdateDevEndpoint",
            "s3:PutBucketPolicy",
            "s3:PutObjectAcl",
        ];
        
        actions.iter()
            .filter(|action| {
                dangerous_actions.iter().any(|dangerous| {
                    action == *dangerous || 
                    (action.ends_with("*") && dangerous.starts_with(&action[..action.len()-1]))
                })
            })
            .cloned()
            .collect()
    }

    /// Find privilege escalation paths in the infrastructure
    fn find_privilege_escalation_paths(&self, graph: &ResourceGraph) -> Vec<AccessPath> {
        let mut paths = Vec::new();
        
        // Get all roles and users
        let roles = graph.get_resources_by_type(&ResourceType::Role);
        let users = graph.get_resources_by_type(&ResourceType::User);
        
        for user in users {
            for role in &roles {
                // Check if user can assume this role
                if self.can_assume_role(graph, user, role) {
                    // Check if role has higher privileges
                    if self.has_higher_privileges(graph, role, user) {
                        let path = AccessPath {
                            id: uuid::Uuid::new_v4(),
                            start_resource: user.id.clone(),
                            end_resource: role.id.clone(),
                            steps: vec![AccessPathStep {
                                from_resource: user.id.clone(),
                                to_resource: role.id.clone(),
                                action: "sts:AssumeRole".to_string(),
                                permission: "iam:PassRole".to_string(),
                                description: format!("User {} can assume role {}", user.name, role.name),
                            }],
                            risk_level: RiskSeverity::High,
                            description: format!("Privilege escalation path from {} to {}", user.name, role.name),
                        };
                        paths.push(path);
                    }
                }
            }
        }
        
        paths
    }

    /// Check if an identity can assume a role
    fn can_assume_role(&self, graph: &ResourceGraph, identity: &CloudResource, role: &CloudResource) -> bool {
        // Check trust relationship
        if let Some(trust_policy) = role.metadata.get("trust_policy") {
            if let Some(principals) = trust_policy.get("Principal") {
                // Check if identity is in the trusted principals
                if let Some(aws_principals) = principals.get("AWS") {
                    if let Some(arr) = aws_principals.as_array() {
                        for principal in arr {
                            if let Some(p) = principal.as_str() {
                                if p.contains(&identity.arn) || p == "*" {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        false
    }

    /// Check if a role has higher privileges than an identity
    fn has_higher_privileges(&self, graph: &ResourceGraph, role: &CloudResource, identity: &CloudResource) -> bool {
        // Simplified check - compare attached policies
        let role_policies = self.get_attached_policies_count(graph, role);
        let identity_policies = self.get_attached_policies_count(graph, identity);
        
        role_policies > identity_policies
    }

    /// Get count of attached policies for a resource
    fn get_attached_policies_count(&self, graph: &ResourceGraph, resource: &CloudResource) -> usize {
        graph.get_connected_resources(&resource.id)
            .iter()
            .filter(|(_, rel)| rel.relationship_type == RelationshipType::AttachedTo)
            .count()
    }

    /// Calculate effective permissions for all identities
    fn calculate_effective_permissions(&self, graph: &ResourceGraph) -> HashMap<String, Vec<String>> {
        let mut permissions = HashMap::new();
        
        let identities = graph.get_resources_by_type(&ResourceType::User);
        
        for identity in identities {
            let mut identity_perms = HashSet::new();
            
            // Get directly attached policies
            let connected = graph.get_connected_resources(&identity.id);
            for (_, rel) in connected {
                if rel.relationship_type == RelationshipType::AttachedTo {
                    if let Some(policy_perms) = self.get_policy_permissions(&rel.target_id) {
                        identity_perms.extend(policy_perms);
                    }
                }
            }
            
            permissions.insert(identity.id.clone(), identity_perms.into_iter().collect());
        }
        
        permissions
    }

    /// Get permissions from a policy
    fn get_policy_permissions(&self, policy_id: &str) -> Option<Vec<String>> {
        // This would normally fetch the policy from cache or database
        None
    }

    /// Identify overly permissive identities
    fn identify_overly_permissive_identities(&self, graph: &ResourceGraph) -> Vec<OverlyPermissiveIdentity> {
        let mut overly_permissive = Vec::new();
        
        let identities = graph.get_resources_by_type(&ResourceType::User);
        
        for identity in identities {
            let mut issues = Vec::new();
            
            // Check for admin-like permissions
            if self.has_admin_permissions(graph, identity) {
                issues.push("Has administrative permissions".to_string());
            }
            
            // Check for wildcard resource access
            if self.has_wildcard_resource_access(graph, identity) {
                issues.push("Has wildcard (*) resource access".to_string());
            }
            
            // Check for ability to modify IAM
            if self.can_modify_iam(graph, identity) {
                issues.push("Can modify IAM policies/roles".to_string());
            }
            
            if !issues.is_empty() {
                overly_permissive.push(OverlyPermissiveIdentity {
                    identity_id: identity.id.clone(),
                    identity_name: identity.name.clone(),
                    identity_type: "User".to_string(),
                    issues,
                    severity: if issues.len() > 1 { RiskSeverity::Critical } else { RiskSeverity::High },
                });
            }
        }
        
        overly_permissive
    }

    fn has_admin_permissions(&self, _graph: &ResourceGraph, _identity: &CloudResource) -> bool {
        // Implementation would check for admin-like permissions
        false
    }

    fn has_wildcard_resource_access(&self, _graph: &ResourceGraph, _identity: &CloudResource) -> bool {
        // Implementation would check for wildcard resource access
        false
    }

    fn can_modify_iam(&self, _graph: &ResourceGraph, _identity: &CloudResource) -> bool {
        // Implementation would check for IAM modification permissions
        false
    }
}

impl Default for IAMAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of IAM analysis
#[derive(Debug, Clone, Default)]
pub struct IAMAnalysisResult {
    pub findings: Vec<IAMFinding>,
    pub escalation_paths: Vec<AccessPath>,
    pub effective_permissions: HashMap<String, Vec<String>>,
    pub overly_permissive: Vec<OverlyPermissiveIdentity>,
}

/// Single IAM finding
#[derive(Debug, Clone)]
pub struct IAMFinding {
    pub policy_name: String,
    pub finding_type: IAMFindingType,
    pub severity: RiskSeverity,
    pub description: String,
    pub recommendation: String,
}

/// Types of IAM findings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IAMFindingType {
    WildcardAction,
    WildcardResource,
    DangerousPermissions,
    MissingCondition,
    OverlyPermissivePrincipal,
    CrossAccountAccess,
}

/// Overly permissive identity
#[derive(Debug, Clone)]
pub struct OverlyPermissiveIdentity {
    pub identity_id: String,
    pub identity_name: String,
    pub identity_type: String,
    pub issues: Vec<String>,
    pub severity: RiskSeverity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iam_analyzer_creation() {
        let analyzer = IAMAnalyzer::new();
        assert!(analyzer.policy_cache.is_empty());
    }

    #[test]
    fn test_dangerous_permissions_detection() {
        let analyzer = IAMAnalyzer::new();
        let actions = vec![
            "s3:GetObject".to_string(),
            "iam:CreateUser".to_string(),
            "ec2:DescribeInstances".to_string(),
        ];
        
        let dangerous = analyzer.check_dangerous_permissions(&actions);
        assert_eq!(dangerous.len(), 1);
        assert_eq!(dangerous[0], "iam:CreateUser");
    }
}
