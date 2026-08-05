//! IAM Security Rules Module
//! 
//! This module implements comprehensive IAM security detection rules
//! for identifying dangerous permissions, privilege escalation paths,
//! and misconfigurations across cloud providers.

use std::sync::Arc;
use crate::models::*;
use crate::models::traits::{SecurityRule, RuleResult};
use crate::graph::ResourceGraph;

/// Rule: IAM Admin Access Without MFA
/// Detects IAM users or roles with administrative privileges that don't require MFA
pub struct IamAdminWithoutMfaRule;

impl SecurityRule for IamAdminWithoutMfaRule {
    fn id(&self) -> &'static str {
        "IAM-001"
    }

    fn name(&self) -> &'static str {
        "IAM Admin Access Without MFA"
    }

    fn description(&self) -> &'static str {
        "Detects IAM users or roles with administrative privileges that do not have multi-factor authentication enabled. \
         Administrative accounts without MFA represent a critical security risk as they can be compromised through \
         credential theft, phishing, or brute force attacks."
    }

    fn category(&self) -> RiskCategory {
        RiskCategory::IdentityAndAccessManagement
    }

    fn severity(&self) -> RiskSeverity {
        RiskSeverity::Critical
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-306") // Missing Authentication for Critical Function
    }

    fn mitre_attack_id(&self) -> Option<&'static str> {
        Some("T1078") // Valid Accounts
    }

    fn compliance_frameworks(&self) -> Vec<&'static str> {
        vec!["SOC2", "ISO27001", "PCI-DSS", "HIPAA", "NIST"]
    }

    fn tags(&self) -> Vec<&'static str> {
        vec!["iam", "mfa", "admin", "authentication", "critical"]
    }

    fn evaluate(&self, resource: &CloudResource, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        // Check if resource is an IAM user or role
        if resource.resource_type != ResourceType::IamUser && resource.resource_type != ResourceType::IamRole {
            return risks;
        }

        // Check for admin privileges
        let has_admin_privileges = self.check_admin_privileges(resource);
        
        if !has_admin_privileges {
            return risks;
        }

        // Check for MFA status
        let mfa_enabled = resource.metadata.get("mfa_enabled")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !mfa_enabled {
            let risk = SecurityRisk::builder()
                .rule_id(self.id())
                .resource_id(resource.id.clone())
                .resource_type(resource.resource_type.clone())
                .severity(self.severity())
                .category(self.category())
                .title(format!("Administrative {} without MFA detected", 
                    if resource.resource_type == ResourceType::IamUser { "user" } else { "role" }))
                .description(format!(
                    "The {} '{}' has administrative privileges but does not have MFA enabled. \
                     This account can perform sensitive actions like creating users, modifying policies, \
                     and accessing critical resources without additional authentication.",
                    if resource.resource_type == ResourceType::IamUser { "user" } else { "role" },
                    resource.name
                ))
                .recommendation(format!(
                    "Enable MFA immediately for this administrative {}. For roles, enforce MFA requirements \
                     in the trust policy. Consider using hardware security keys for highest security.",
                    if resource.resource_type == ResourceType::IamUser { "user" } else { "role" }
                ))
                .cwe_id(self.cwe_id().map(String::from))
                .mitre_attack_id(self.mitre_attack_id().map(String::from))
                .compliance_impacts(self.compliance_frameworks().iter().map(|s| s.to_string()).collect())
                .build();

            risks.push(risk);
        }

        risks
    }

    fn auto_remediate(&self, resource: &mut CloudResource) -> Option<String> {
        // Auto-remediation would require cloud provider API access
        // This is a placeholder for the remediation logic
        resource.metadata.insert("mfa_enforced".to_string(), "pending".to_string());
        Some(format!("MFA enforcement initiated for {}", resource.id))
    }
}

impl IamAdminWithoutMfaRule {
    fn check_admin_privileges(&self, resource: &CloudResource) -> bool {
        // Check for explicit admin policies
        if let Some(policies) = resource.metadata.get("attached_policies") {
            let admin_policies = ["AdministratorAccess", "admin", "full-access", "*"];
            if admin_policies.iter().any(|p| policies.contains(p)) {
                return true;
            }
        }

        // Check for wildcard permissions in inline policies
        if let Some(inline_policies) = resource.metadata.get("inline_policies") {
            if inline_policies.contains("*:*") || inline_policies.contains("*") {
                return true;
            }
        }

        false
    }
}

/// Rule: Overly Permissive IAM Policy
/// Detects IAM policies with overly broad permissions
pub struct OverlyPermissivePolicyRule;

impl SecurityRule for OverlyPermissivePolicyRule {
    fn id(&self) -> &'static str {
        "IAM-002"
    }

    fn name(&self) -> &'static str {
        "Overly Permissive IAM Policy"
    }

    fn description(&self) -> &'static str {
        "Detects IAM policies that grant overly broad permissions, such as wildcard (*) actions or resources. \
         Overly permissive policies violate the principle of least privilege and increase the attack surface \
         if credentials are compromised."
    }

    fn category(&self) -> RiskCategory {
        RiskCategory::IdentityAndAccessManagement
    }

    fn severity(&self) -> RiskSeverity {
        RiskSeverity::High
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-269") // Improper Privilege Management
    }

    fn mitre_attack_id(&self) -> Option<&'static str> {
        Some("T1078.004") // Cloud Accounts
    }

    fn compliance_frameworks(&self) -> Vec<&'static str> {
        vec!["SOC2", "ISO27001", "PCI-DSS", "NIST", "CIS"]
    }

    fn tags(&self) -> Vec<&'static str> {
        vec!["iam", "policy", "permissions", "least-privilege", "wildcard"]
    }

    fn evaluate(&self, resource: &CloudResource, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        if resource.resource_type != ResourceType::IamPolicy {
            return risks;
        }

        let policy_document = resource.metadata.get("policy_document")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Check for wildcard actions
        let has_wildcard_actions = policy_document.contains("\"Action\": \"*\"") 
            || policy_document.contains("\"Action\":[\"*\"]")
            || policy_document.contains("'Action': '*'");

        // Check for wildcard resources
        let has_wildcard_resources = policy_document.contains("\"Resource\": \"*\"")
            || policy_document.contains("\"Resource\":[\"*\"]")
            || policy_document.contains("'Resource': '*'");

        // Check for wildcard in specific dangerous services
        let dangerous_wildcards = [
            "iam:*",
            "sts:*",
            "organizations:*",
            "account:*",
            "kms:*",
            "secretsmanager:*",
        ];

        let has_dangerous_service_wildcard = dangerous_wildcards.iter()
            .any(|pattern| policy_document.contains(pattern));

        if has_wildcard_actions || has_wildcard_resources || has_dangerous_service_wildcard {
            let mut issues = Vec::new();
            
            if has_wildcard_actions {
                issues.push("wildcard actions (*)");
            }
            if has_wildcard_resources {
                issues.push("wildcard resources (*)");
            }
            if has_dangerous_service_wildcard {
                issues.push("wildcard permissions on critical services");
            }

            let risk = SecurityRisk::builder()
                .rule_id(self.id())
                .resource_id(resource.id.clone())
                .resource_type(resource.resource_type.clone())
                .severity(self.severity())
                .category(self.category())
                .title("Overly permissive IAM policy detected".to_string())
                .description(format!(
                    "The IAM policy '{}' contains overly broad permissions including: {}. \
                     This policy grants excessive access that violates the principle of least privilege \
                     and could allow unauthorized access to sensitive resources if compromised.",
                    resource.name,
                    issues.join(", ")
                ))
                .recommendation(
                    "Review and restrict the policy permissions to only what is required. \
                     Replace wildcards with specific actions and resources. Use AWS Access Analyzer \
                     or equivalent tools to identify minimum required permissions.".to_string()
                )
                .cwe_id(self.cwe_id().map(String::from))
                .mitre_attack_id(self.mitre_attack_id().map(String::from))
                .compliance_impacts(self.compliance_frameworks().iter().map(|s| s.to_string()).collect())
                .build();

            risks.push(risk);
        }

        risks
    }

    fn auto_remediate(&self, resource: &mut CloudResource) -> Option<String> {
        resource.metadata.insert("policy_review_required".to_string(), "true".to_string());
        Some(format!("Policy {} flagged for manual review and restriction", resource.id))
    }
}

/// Rule: IAM User With Console Access But No Password Policy
/// Detects IAM users with console access that don't comply with password policies
pub struct IamConsoleNoPasswordPolicyRule;

impl SecurityRule for IamConsoleNoPasswordPolicyRule {
    fn id(&self) -> &'static str {
        "IAM-003"
    }

    fn name(&self) -> &'static str {
        "IAM Console Access Without Strong Password Policy"
    }

    fn description(&self) -> &'static str {
        "Detects IAM users with console access where the account password does not meet strong password \
         policy requirements or where no password policy is enforced. Weak passwords are susceptible \
         to brute force and credential stuffing attacks."
    }

    fn category(&self) -> RiskCategory {
        RiskCategory::IdentityAndAccessManagement
    }

    fn severity(&self) -> RiskSeverity {
        RiskSeverity::Medium
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-521") // Weak Password Requirements
    }

    fn mitre_attack_id(&self) -> Option<&'static str> {
        Some("T1110") // Brute Force
    }

    fn compliance_frameworks(&self) -> Vec<&'static str> {
        vec!["SOC2", "ISO27001", "PCI-DSS", "NIST"]
    }

    fn tags(&self) -> Vec<&'static str> {
        vec!["iam", "password", "console", "authentication", "policy"]
    }

    fn evaluate(&self, resource: &CloudResource, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        if resource.resource_type != ResourceType::IamUser {
            return risks;
        }

        // Check if user has console access
        let has_console_access = resource.metadata.get("console_access")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !has_console_access {
            return risks;
        }

        // Check password policy compliance
        let password_policy_enforced = resource.metadata.get("password_policy_compliant")
            .map(|v| v == "true")
            .unwrap_or(false);

        let password_age_days = resource.metadata.get("password_last_changed_days")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(-1);

        let mut issues = Vec::new();

        if !password_policy_enforced {
            issues.push("password does not meet policy requirements");
        }

        if password_age_days > 90 {
            issues.push(format!("password is {} days old (recommended rotation: 90 days)", password_age_days));
        }

        if !issues.is_empty() {
            let risk = SecurityRisk::builder()
                .rule_id(self.id())
                .resource_id(resource.id.clone())
                .resource_type(resource.resource_type.clone())
                .severity(self.severity())
                .category(self.category())
                .title("Weak password configuration for console user".to_string())
                .description(format!(
                    "The IAM user '{}' has console access with the following issues: {}. \
                     This increases the risk of account compromise through password guessing or credential theft.",
                    resource.name,
                    issues.join(", ")
                ))
                .recommendation(
                    "Enforce strong password policies requiring minimum length, complexity, and regular rotation. \
                     Enable MFA for all console users. Consider using SSO with identity providers for better security.".to_string()
                )
                .cwe_id(self.cwe_id().map(String::from))
                .mitre_attack_id(self.mitre_attack_id().map(String::from))
                .compliance_impacts(self.compliance_frameworks().iter().map(|s| s.to_string()).collect())
                .build();

            risks.push(risk);
        }

        risks
    }

    fn auto_remediate(&self, resource: &mut CloudResource) -> Option<String> {
        resource.metadata.insert("password_reset_required".to_string(), "true".to_string());
        Some(format!("Password reset required for user {}", resource.id))
    }
}

/// Rule: IAM Role With Excessive Trust Policy
/// Detects IAM roles with overly permissive trust policies
pub struct ExcessiveTrustPolicyRule;

impl SecurityRule for ExcessiveTrustPolicyRule {
    fn id(&self) -> &'static str {
        "IAM-004"
    }

    fn name(&self) -> &'static str {
        "IAM Role With Excessive Trust Policy"
    }

    fn description(&self) -> &'static str {
        "Detects IAM roles with trust policies that allow assumption by overly broad principals, \
         including wildcard principals, any AWS account, or external accounts without proper controls. \
         Excessive trust policies can lead to unauthorized role assumption and privilege escalation."
    }

    fn category(&self) -> RiskCategory {
        RiskCategory::IdentityAndAccessManagement
    }

    fn severity(&self) -> RiskSeverity {
        RiskSeverity::High
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-269") // Improper Privilege Management
    }

    fn mitre_attack_id(&self) -> Option<&'static str> {
        Some("T1078.004") // Cloud Accounts
    }

    fn compliance_frameworks(&self) -> Vec<&'static str> {
        vec!["SOC2", "ISO27001", "PCI-DSS", "NIST", "CIS"]
    }

    fn tags(&self) -> Vec<&'static str> {
        vec!["iam", "trust-policy", "role-assumption", "cross-account", "privilege-escalation"]
    }

    fn evaluate(&self, resource: &CloudResource, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        if resource.resource_type != ResourceType::IamRole {
            return risks;
        }

        let trust_policy = resource.metadata.get("trust_policy")
            .map(|s| s.as_str())
            .unwrap_or("");

        let mut issues = Vec::new();

        // Check for wildcard principal
        if trust_policy.contains("\"Principal\": \"*\"") || trust_policy.contains("\"Principal\":{\"AWS\":\"*\"}") {
            issues.push("allows assumption by any principal (wildcard)");
        }

        // Check for any AWS account
        if trust_policy.contains("\"AWS\": \"*\"") {
            issues.push("allows assumption from any AWS account");
        }

        // Check for anonymous access
        if trust_policy.contains("arn:aws:iam::000000000000") {
            issues.push("allows anonymous/external account access");
        }

        // Check for missing conditions
        let has_conditions = trust_policy.contains("\"Condition\"");
        if !has_issues && !has_conditions {
            // Only flag if there are cross-account trusts without conditions
            let has_cross_account = trust_policy.contains("arn:aws:iam::") 
                && !trust_policy.contains(&format!("arn:aws:iam::{}:", 
                    resource.metadata.get("owner_account").unwrap_or(&String::new())));
            
            if has_cross_account {
                issues.push("cross-account trust without conditions");
            }
        }

        if !issues.is_empty() {
            let risk = SecurityRisk::builder()
                .rule_id(self.id())
                .resource_id(resource.id.clone())
                .resource_type(resource.resource_type.clone())
                .severity(self.severity())
                .category(self.category())
                .title("Excessive trust policy detected".to_string())
                .description(format!(
                    "The IAM role '{}' has a trust policy with the following issues: {}. \
                     This configuration could allow unauthorized entities to assume this role and gain access \
                     to resources and permissions associated with the role.",
                    resource.name,
                    issues.join(", ")
                ))
                .recommendation(
                    "Restrict the trust policy to specific, known principals. Add conditions to limit \
                     role assumption based on source IP, MFA status, or external ID. Regularly review \
                     and audit role trust relationships.".to_string()
                )
                .cwe_id(self.cwe_id().map(String::from))
                .mitre_attack_id(self.mitre_attack_id().map(String::from))
                .compliance_impacts(self.compliance_frameworks().iter().map(|s| s.to_string()).collect())
                .build();

            risks.push(risk);
        }

        risks
    }

    fn auto_remediate(&self, resource: &mut CloudResource) -> Option<String> {
        resource.metadata.insert("trust_policy_review_required".to_string(), "true".to_string());
        Some(format!("Trust policy for role {} flagged for review", resource.id))
    }
}

/// Rule: Service Account With Excessive Permissions
/// Detects Kubernetes service accounts or cloud service accounts with excessive permissions
pub struct ServiceAccountExcessivePermissionsRule;

impl SecurityRule for ServiceAccountExcessivePermissionsRule {
    fn id(&self) -> &'static str {
        "IAM-005"
    }

    fn name(&self) -> &'static str {
        "Service Account With Excessive Permissions"
    }

    fn description(&self) -> &'static str {
        "Detects service accounts (Kubernetes, GCP, Azure) that have been granted excessive permissions \
         beyond their operational requirements. Service accounts with excessive permissions increase \
         the blast radius if compromised."
    }

    fn category(&self) -> RiskCategory {
        RiskCategory::IdentityAndAccessManagement
    }

    fn severity(&self) -> RiskSeverity {
        RiskSeverity::High
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-269") // Improper Privilege Management
    }

    fn mitre_attack_id(&self) -> Option<&'static str> {
        Some("T1078.004") // Cloud Accounts
    }

    fn compliance_frameworks(&self) -> Vec<&'static str> {
        vec!["SOC2", "ISO27001", "PCI-DSS", "CIS-Kubernetes"]
    }

    fn tags(&self) -> Vec<&'static str> {
        vec!["service-account", "kubernetes", "rbac", "least-privilege", "iam"]
    }

    fn evaluate(&self, resource: &CloudResource, graph: &ResourceGraph) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        // Check for Kubernetes service accounts
        if resource.resource_type != ResourceType::ServiceAccount 
            && resource.resource_type != ResourceType::IamServiceAccount {
            return risks;
        }

        let bound_permissions = resource.metadata.get("bound_permissions")
            .map(|s| s.as_str())
            .unwrap_or("");

        let cluster_role = resource.metadata.get("cluster_role")
            .map(|s| s.as_str())
            .unwrap_or("");

        let mut issues = Vec::new();

        // Check for cluster-admin binding
        if cluster_role == "cluster-admin" {
            issues.push("bound to cluster-admin role");
        }

        // Check for wildcard permissions
        if bound_permissions.contains("*:*") || bound_permissions.contains("'*':'*'") {
            issues.push("has wildcard permissions");
        }

        // Check for secrets access
        if bound_permissions.contains("secrets") && bound_permissions.contains("*") {
            issues.push("has unrestricted access to secrets");
        }

        // Check for pod creation capabilities
        if bound_permissions.contains("pods") && bound_permissions.contains("create") {
            if bound_permissions.contains("exec") || bound_permissions.contains("attach") {
                issues.push("can create pods and exec/attach (potential container escape)");
            }
        }

        if !issues.is_empty() {
            let risk = SecurityRisk::builder()
                .rule_id(self.id())
                .resource_id(resource.id.clone())
                .resource_type(resource.resource_type.clone())
                .severity(self.severity())
                .category(self.category())
                .title("Service account with excessive permissions".to_string())
                .description(format!(
                    "The service account '{}' has the following excessive permissions: {}. \
                     This increases the risk of lateral movement and privilege escalation if the \
                     service account credentials are compromised.",
                    resource.name,
                    issues.join(", ")
                ))
                .recommendation(
                    "Apply the principle of least privilege to service accounts. Remove cluster-admin \
                     bindings where possible. Use namespace-scoped roles instead of cluster roles. \
                     Regularly audit service account permissions.".to_string()
                )
                .cwe_id(self.cwe_id().map(String::from))
                .mitre_attack_id(self.mitre_attack_id().map(String::from))
                .compliance_impacts(self.compliance_frameworks().iter().map(|s| s.to_string()).collect())
                .build();

            risks.push(risk);
        }

        risks
    }

    fn auto_remediate(&self, resource: &mut CloudResource) -> Option<String> {
        resource.metadata.insert("permissions_audit_required".to_string(), "true".to_string());
        Some(format!("Service account {} permissions flagged for audit", resource.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iam_admin_without_mfa_rule_creation() {
        let rule = IamAdminWithoutMfaRule;
        assert_eq!(rule.id(), "IAM-001");
        assert_eq!(rule.severity(), RiskSeverity::Critical);
    }

    #[test]
    fn test_overly_permissive_policy_rule_creation() {
        let rule = OverlyPermissivePolicyRule;
        assert_eq!(rule.id(), "IAM-002");
        assert_eq!(rule.severity(), RiskSeverity::High);
    }

    #[test]
    fn test_console_password_policy_rule_creation() {
        let rule = IamConsoleNoPasswordPolicyRule;
        assert_eq!(rule.id(), "IAM-003");
        assert_eq!(rule.severity(), RiskSeverity::Medium);
    }

    #[test]
    fn test_excessive_trust_policy_rule_creation() {
        let rule = ExcessiveTrustPolicyRule;
        assert_eq!(rule.id(), "IAM-004");
        assert_eq!(rule.severity(), RiskSeverity::High);
    }

    #[test]
    fn test_service_account_permissions_rule_creation() {
        let rule = ServiceAccountExcessivePermissionsRule;
        assert_eq!(rule.id(), "IAM-005");
        assert_eq!(rule.severity(), RiskSeverity::High);
    }
}
