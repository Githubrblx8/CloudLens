//! Core data models for CloudLens

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Unique identifier for cloud resources
pub type ResourceId = String;

/// Cloud provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    AWS,
    Azure,
    GCP,
    Kubernetes,
    Unknown,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProvider::AWS => write!(f, "AWS"),
            CloudProvider::Azure => write!(f, "Azure"),
            CloudProvider::GCP => write!(f, "GCP"),
            CloudProvider::Kubernetes => write!(f, "Kubernetes"),
            CloudProvider::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Resource types in cloud infrastructure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    // Compute
    VM,
    Container,
    Pod,
    Lambda,
    Function,
    
    // Storage
    Bucket,
    Database,
    Disk,
    
    // Network
    VPC,
    Subnet,
    SecurityGroup,
    LoadBalancer,
    Gateway,
    
    // IAM
    User,
    Group,
    Role,
    Policy,
    ServiceAccount,
    
    // Other
    Secret,
    Key,
    Certificate,
    Custom(String),
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::VM => write!(f, "Virtual Machine"),
            ResourceType::Container => write!(f, "Container"),
            ResourceType::Pod => write!(f, "Pod"),
            ResourceType::Lambda => write!(f, "Lambda Function"),
            ResourceType::Function => write!(f, "Function"),
            ResourceType::Bucket => write!(f, "Storage Bucket"),
            ResourceType::Database => write!(f, "Database"),
            ResourceType::Disk => write!(f, "Disk"),
            ResourceType::VPC => write!(f, "VPC"),
            ResourceType::Subnet => write!(f, "Subnet"),
            ResourceType::SecurityGroup => write!(f, "Security Group"),
            ResourceType::LoadBalancer => write!(f, "Load Balancer"),
            ResourceType::Gateway => write!(f, "Gateway"),
            ResourceType::User => write!(f, "User"),
            ResourceType::Group => write!(f, "Group"),
            ResourceType::Role => write!(f, "Role"),
            ResourceType::Policy => write!(f, "Policy"),
            ResourceType::ServiceAccount => write!(f, "Service Account"),
            ResourceType::Secret => write!(f, "Secret"),
            ResourceType::Key => write!(f, "Key"),
            ResourceType::Certificate => write!(f, "Certificate"),
            ResourceType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Risk severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for RiskSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskSeverity::Critical => write!(f, "CRITICAL"),
            RiskSeverity::High => write!(f, "HIGH"),
            RiskSeverity::Medium => write!(f, "MEDIUM"),
            RiskSeverity::Low => write!(f, "LOW"),
            RiskSeverity::Info => write!(f, "INFO"),
        }
    }
}

/// Risk categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    ExposedResource,
    ExcessivePermissions,
    WeakAuthentication,
    MissingEncryption,
    NetworkMisconfiguration,
    SecretExposure,
    ComplianceViolation,
    IdentityRisk,
    DataRisk,
    Custom(String),
}

impl std::fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskCategory::ExposedResource => write!(f, "Exposed Resource"),
            RiskCategory::ExcessivePermissions => write!(f, "Excessive Permissions"),
            RiskCategory::WeakAuthentication => write!(f, "Weak Authentication"),
            RiskCategory::MissingEncryption => write!(f, "Missing Encryption"),
            RiskCategory::NetworkMisconfiguration => write!(f, "Network Misconfiguration"),
            RiskCategory::SecretExposure => write!(f, "Secret Exposure"),
            RiskCategory::ComplianceViolation => write!(f, "Compliance Violation"),
            RiskCategory::IdentityRisk => write!(f, "Identity Risk"),
            RiskCategory::DataRisk => write!(f, "Data Risk"),
            RiskCategory::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// A cloud resource node in the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    pub id: ResourceId,
    pub arn: String,
    pub name: String,
    pub resource_type: ResourceType,
    pub provider: CloudProvider,
    pub region: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub tags: HashMap<String, String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub is_public: bool,
    pub encryption_status: EncryptionStatus,
}

/// Encryption status of a resource
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionStatus {
    Enabled,
    Disabled,
    Partial,
    Unknown,
}

/// Relationship between resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRelationship {
    pub source_id: ResourceId,
    pub target_id: ResourceId,
    pub relationship_type: RelationshipType,
    pub description: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of relationships between resources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    // Ownership
    Owns,
    Contains,
    Manages,
    
    // Network
    ConnectsTo,
    RoutesTo,
    Protects,
    Exposes,
    
    // IAM
    HasPermission,
    AssumesRole,
    AttachedTo,
    Trusts,
    
    // Data flow
    ReadsFrom,
    WritesTo,
    DependsOn,
    
    // Custom
    Custom(String),
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::Owns => write!(f, "owns"),
            RelationshipType::Contains => write!(f, "contains"),
            RelationshipType::Manages => write!(f, "manages"),
            RelationshipType::ConnectsTo => write!(f, "connects to"),
            RelationshipType::RoutesTo => write!(f, "routes to"),
            RelationshipType::Protects => write!(f, "protects"),
            RelationshipType::Exposes => write!(f, "exposes"),
            RelationshipType::HasPermission => write!(f, "has permission"),
            RelationshipType::AssumesRole => write!(f, "assumes role"),
            RelationshipType::AttachedTo => write!(f, "attached to"),
            RelationshipType::Trusts => write!(f, "trusts"),
            RelationshipType::ReadsFrom => write!(f, "reads from"),
            RelationshipType::WritesTo => write!(f, "writes to"),
            RelationshipType::DependsOn => write!(f, "depends on"),
            RelationshipType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// A detected security risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRisk {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: RiskSeverity,
    pub category: RiskCategory,
    pub affected_resources: Vec<ResourceId>,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub mitre_attack_id: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// IAM Policy document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMPolicy {
    pub id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub version: String,
    pub statements: Vec<IAMStatement>,
    pub attached_to: Vec<ResourceId>,
}

/// IAM Policy Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMStatement {
    pub effect: IAMEffect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub condition: Option<serde_json::Value>,
    pub principal: Option<IAMPrincipal>,
}

/// IAM Effect (Allow/Deny)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum IAMEffect {
    Allow,
    Deny,
}

/// IAM Principal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMPrincipal {
    pub aws: Option<Vec<String>>,
    pub service: Option<Vec<String>>,
    pub federated: Option<Vec<String>>,
}

/// Access path representing a potential attack vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPath {
    pub id: Uuid,
    pub start_resource: ResourceId,
    pub end_resource: ResourceId,
    pub steps: Vec<AccessPathStep>,
    pub risk_level: RiskSeverity,
    pub description: String,
}

/// Single step in an access path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPathStep {
    pub from_resource: ResourceId,
    pub to_resource: ResourceId,
    pub action: String,
    pub permission: String,
    pub description: String,
}

/// Infrastructure scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub provider: CloudProvider,
    pub account_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub resources_found: usize,
    pub risks_detected: usize,
    pub summary: ScanSummary,
    pub errors: Vec<String>,
}

/// Scan status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Partial,
}

/// Summary of scan results
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub total_resources: usize,
    pub public_resources: usize,
    pub encrypted_resources: usize,
    pub unencrypted_resources: usize,
    pub risks_by_severity: HashMap<RiskSeverity, usize>,
    pub risks_by_category: HashMap<RiskCategory, usize>,
    pub resource_types: HashMap<ResourceType, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_type_display() {
        assert_eq!(format!("{}", ResourceType::VM), "Virtual Machine");
        assert_eq!(format!("{}", ResourceType::Bucket), "Storage Bucket");
    }

    #[test]
    fn test_risk_severity_ordering() {
        assert!(RiskSeverity::Critical > RiskSeverity::High);
        assert!(RiskSeverity::High > RiskSeverity::Medium);
    }
}
