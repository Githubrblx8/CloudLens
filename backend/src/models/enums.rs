//! CloudLens Enumeration Types
//! 
//! This module defines all enumeration types used throughout the platform,
//! including cloud providers, resource types, risk classifications, and more.

use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};
use utoipa::ToSchema;

/// =============================================================================
/// CLOUD PROVIDER ENUMERATIONS
/// =============================================================================

/// Supported cloud providers for analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum CloudProvider {
    /// Amazon Web Services
    #[serde(alias = "AWS", alias = "aws")]
    Aws,
    
    /// Microsoft Azure
    #[serde(alias = "AZURE", alias = "azure")]
    Azure,
    
    /// Google Cloud Platform
    #[serde(alias = "GCP", alias = "gcp", alias = "google_cloud")]
    Gcp,
    
    /// Kubernetes Cluster
    #[serde(alias = "K8S", alias = "kubernetes", alias = "kubernetes_cluster")]
    Kubernetes,
    
    /// On-premises infrastructure
    #[serde(alias = "ONPREM", alias = "onpremises", alias = "on_premises")]
    OnPremises,
    
    /// Multi-cloud aggregation
    #[serde(alias = "MULTICLOUD", alias = "multi_cloud")]
    MultiCloud,
    
    /// Unknown or custom provider
    #[serde(alias = "UNKNOWN", alias = "other")]
    Unknown,
}

impl CloudProvider {
    /// Returns a human-readable name for the provider
    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "Amazon Web Services",
            CloudProvider::Azure => "Microsoft Azure",
            CloudProvider::Gcp => "Google Cloud Platform",
            CloudProvider::Kubernetes => "Kubernetes Cluster",
            CloudProvider::OnPremises => "On-Premises Infrastructure",
            CloudProvider::MultiCloud => "Multi-Cloud Environment",
            CloudProvider::Unknown => "Unknown Provider",
        }
    }
    
    /// Returns supported services for this provider
    pub fn supported_services(&self) -> Vec<&'static str> {
        match self {
            CloudProvider::Aws => vec![
                "EC2", "S3", "RDS", "Lambda", "IAM", "VPC", "EKS", "DynamoDB",
                "Redshift", "ElastiCache", "SQS", "SNS", "CloudFormation", "CloudTrail"
            ],
            CloudProvider::Azure => vec![
                "Virtual Machines", "Blob Storage", "SQL Database", "Functions",
                "Active Directory", "Virtual Network", "AKS", "Cosmos DB"
            ],
            CloudProvider::Gcp => vec![
                "Compute Engine", "Cloud Storage", "Cloud SQL", "Cloud Functions",
                "IAM", "VPC", "GKE", "BigQuery", "Pub/Sub"
            ],
            CloudProvider::Kubernetes => vec![
                "Pods", "Deployments", "Services", "ConfigMaps", "Secrets",
                "Namespaces", "RBAC", "Ingress", "PersistentVolumes"
            ],
            CloudProvider::OnPremises => vec![
                "Virtual Machines", "Physical Servers", "Network Devices",
                "Storage Arrays", "Databases"
            ],
            CloudProvider::MultiCloud => vec![],
            CloudProvider::Unknown => vec![],
        }
    }
}

/// =============================================================================
/// RESOURCE TYPE ENUMERATIONS
/// =============================================================================

/// Types of cloud resources that can be analyzed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ResourceType {
    // Compute Resources
    VirtualMachine,
    Container,
    Pod,
    LambdaFunction,
    ServerlessFunction,
    
    // Storage Resources
    ObjectStorage,
    BlockStorage,
    FileStorage,
    Database,
    Cache,
    
    // Network Resources
    Vpc,
    Subnet,
    SecurityGroup,
    Firewall,
    LoadBalancer,
    Gateway,
    DnsZone,
    Cdn,
    
    // IAM Resources
    User,
    Group,
    Role,
    Policy,
    ServiceAccount,
    
    // Application Resources
    ApiGateway,
    Queue,
    Topic,
    Stream,
    
    // Management Resources
    CloudformationStack,
    ResourceGroup,
    Namespace,
    Cluster,
    
    // Special Resources
    Secret,
    Key,
    Certificate,
    Image,
    Snapshot,
    
    // Unknown
    Unknown,
}

impl ResourceType {
    /// Returns the category of this resource type
    pub fn category(&self) -> &'static str {
        match self {
            ResourceType::VirtualMachine | ResourceType::Container | 
            ResourceType::Pod | ResourceType::LambdaFunction | 
            ResourceType::ServerlessFunction => "Compute",
            
            ResourceType::ObjectStorage | ResourceType::BlockStorage | 
            ResourceType::FileStorage | ResourceType::Database | 
            ResourceType::Cache => "Storage",
            
            ResourceType::Vpc | ResourceType::Subnet | ResourceType::SecurityGroup | 
            ResourceType::Firewall | ResourceType::LoadBalancer | 
            ResourceType::Gateway | ResourceType::DnsZone | ResourceType::Cdn => "Network",
            
            ResourceType::User | ResourceType::Group | ResourceType::Role | 
            ResourceType::Policy | ResourceType::ServiceAccount => "IAM",
            
            ResourceType::ApiGateway | ResourceType::Queue | 
            ResourceType::Topic | ResourceType::Stream => "Application",
            
            ResourceType::CloudformationStack | ResourceType::ResourceGroup | 
            ResourceType::Namespace | ResourceType::Cluster => "Management",
            
            ResourceType::Secret | ResourceType::Key | 
            ResourceType::Certificate | ResourceType::Image | 
            ResourceType::Snapshot => "Special",
            
            ResourceType::Unknown => "Unknown",
        }
    }
    
    /// Returns common risk patterns for this resource type
    pub fn common_risks(&self) -> Vec<&'static str> {
        match self {
            ResourceType::Database => vec![
                "Public accessibility",
                "Unencrypted storage",
                "Weak authentication",
                "Excessive permissions"
            ],
            ResourceType::ObjectStorage => vec![
                "Public bucket policy",
                "Missing encryption",
                "No versioning enabled",
                "Overly permissive CORS"
            ],
            ResourceType::VirtualMachine => vec![
                "Public IP exposure",
                "Open security groups",
                "Outdated OS/packages",
                "Hardcoded credentials"
            ],
            ResourceType::Role | ResourceType::User => vec![
                "Privilege escalation path",
                "Overly permissive policies",
                "Cross-account trust issues",
                "No MFA enforced"
            ],
            _ => vec![],
        }
    }
}

/// =============================================================================
/// RISK CLASSIFICATION ENUMERATIONS
/// =============================================================================

/// Severity levels for security risks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum RiskSeverity {
    /// Informational - no immediate action required
    Informational,
    /// Low - minor issue, should be addressed
    Low,
    /// Medium - significant issue, should be prioritized
    Medium,
    /// High - serious vulnerability, requires immediate attention
    High,
    /// Critical - severe vulnerability, emergency response needed
    Critical,
}

impl RiskSeverity {
    /// Returns numeric score for severity (0-100)
    pub fn score(&self) -> u8 {
        match self {
            RiskSeverity::Informational => 0,
            RiskSeverity::Low => 25,
            RiskSeverity::Medium => 50,
            RiskSeverity::High => 75,
            RiskSeverity::Critical => 100,
        }
    }
    
    /// Returns color code for UI display
    pub fn color_code(&self) -> &'static str {
        match self {
            RiskSeverity::Informational => "#6B7280",
            RiskSeverity::Low => "#10B981",
            RiskSeverity::Medium => "#F59E0B",
            RiskSeverity::High => "#EF4444",
            RiskSeverity::Critical => "#DC2626",
        }
    }
    
    /// Returns SLA recommendation for remediation
    pub fn remediation_sla(&self) -> &'static str {
        match self {
            RiskSeverity::Informational => "No specific timeline",
            RiskSeverity::Low => "Within 90 days",
            RiskSeverity::Medium => "Within 30 days",
            RiskSeverity::High => "Within 7 days",
            RiskSeverity::Critical => "Within 24 hours",
        }
    }
}

/// Categories of security risks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum RiskCategory {
    /// Identity and Access Management issues
    Iam,
    /// Network security issues
    Network,
    /// Data protection issues
    DataProtection,
    /// Logging and monitoring gaps
    LoggingMonitoring,
    /// Encryption issues
    Encryption,
    /// Compliance violations
    Compliance,
    /// Configuration errors
    Misconfiguration,
    /// Credential exposure
    CredentialExposure,
    /// Privilege escalation paths
    PrivilegeEscalation,
    /// Lateral movement paths
    LateralMovement,
    /// Persistence mechanisms
    Persistence,
    /// Supply chain risks
    SupplyChain,
    /// API security issues
    ApiSecurity,
    /// Container security issues
    ContainerSecurity,
    /// Serverless security issues
    ServerlessSecurity,
}

impl RiskCategory {
    /// Returns description of the category
    pub fn description(&self) -> &'static str {
        match self {
            RiskCategory::Iam => "Issues related to identity and access management",
            RiskCategory::Network => "Network security and segmentation issues",
            RiskCategory::DataProtection => "Data privacy and protection concerns",
            RiskCategory::LoggingMonitoring => "Insufficient logging or monitoring capabilities",
            RiskCategory::Encryption => "Missing or weak encryption implementations",
            RiskCategory::Compliance => "Violations of compliance frameworks",
            RiskCategory::Misconfiguration => "Incorrect or insecure configurations",
            RiskCategory::CredentialExposure => "Exposed or leaked credentials",
            RiskCategory::PrivilegeEscalation => "Paths allowing privilege escalation",
            RiskCategory::LateralMovement => "Paths enabling lateral movement",
            RiskCategory::Persistence => "Mechanisms for persistent access",
            RiskCategory::SupplyChain => "Third-party or supply chain vulnerabilities",
            RiskCategory::ApiSecurity => "API endpoint security issues",
            RiskCategory::ContainerSecurity => "Container-specific security concerns",
            RiskCategory::ServerlessSecurity => "Serverless function security issues",
        }
    }
    
    /// Returns related MITRE ATT&CK tactics
    pub fn mitre_tactics(&self) -> Vec<&'static str> {
        match self {
            RiskCategory::Iam => vec!["TA0006"], // Credential Access
            RiskCategory::PrivilegeEscalation => vec!["TA0004"], // Privilege Escalation
            RiskCategory::LateralMovement => vec!["TA0008"], // Lateral Movement
            RiskCategory::Persistence => vec!["TA0003"], // Persistence
            RiskCategory::CredentialExposure => vec!["TA0006"], // Credential Access
            _ => vec![],
        }
    }
}

/// Status of a detected risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum RiskStatus {
    /// Newly detected risk
    New,
    /// Risk is being investigated
    Investigating,
    /// Risk has been acknowledged
    Acknowledged,
    /// Remediation is in progress
    RemediationInProgress,
    /// Risk has been mitigated
    Mitigated,
    /// Risk was a false positive
    FalsePositive,
    /// Risk has been accepted
    Accepted,
    /// Risk has been re-detected
    Recurrent,
}

/// =============================================================================
/// IAM ENUMERATIONS
/// =============================================================================

/// Effect of an IAM statement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum IamEffect {
    Allow,
    Deny,
}

/// Common IAM actions across providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum IamAction {
    // Read operations
    Read,
    List,
    Describe,
    Get,
    
    // Write operations
    Create,
    Update,
    Delete,
    Put,
    
    // Administrative operations
    Administer,
    Manage,
    Configure,
    
    // IAM specific
    PassRole,
    AssumeRole,
    AttachPolicy,
    CreatePolicy,
    DeletePolicy,
    
    // Wildcard
    All,
    Wildcard,
}

/// Access level for IAM actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AccessLevel {
    ReadOnly,
    LimitedWrite,
    FullWrite,
    Administrative,
    FullAccess,
}

impl AccessLevel {
    /// Returns numeric privilege score
    pub fn privilege_score(&self) -> u8 {
        match self {
            AccessLevel::ReadOnly => 10,
            AccessLevel::LimitedWrite => 30,
            AccessLevel::FullWrite => 60,
            AccessLevel::Administrative => 80,
            AccessLevel::FullAccess => 100,
        }
    }
}

/// =============================================================================
/// NETWORK ENUMERATIONS
/// =============================================================================

/// Type of network connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ConnectionType {
    Direct,
    Peered,
    Vpn,
    TransitGateway,
    Proxy,
    LoadBalanced,
    NatGateway,
    InternetGateway,
    PrivateLink,
    ServiceEndpoint,
}

/// Network visibility level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum NetworkVisibility {
    Public,
    Internal,
    Private,
    Isolated,
}

/// =============================================================================
/// COMPLIANCE ENUMERATIONS
/// =============================================================================

/// Supported compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceFramework {
    // General
    Soc2,
    Iso27001,
    Nist800_53,
    NistCsf,
    
    // Industry specific
    Hipaa,
    PciDss,
    Fedramp,
    Gdpr,
    Ccjpa,
    
    // Cloud specific
    CisAws,
    CisAzure,
    CisGcp,
    CisKubernetes,
    
    // Regional
    Hds,
    Bsi,
}

impl ComplianceFramework {
    /// Returns full name of the framework
    pub fn full_name(&self) -> &'static str {
        match self {
            ComplianceFramework::Soc2 => "SOC 2 Type II",
            ComplianceFramework::Iso27001 => "ISO/IEC 27001",
            ComplianceFramework::Nist800_53 => "NIST SP 800-53",
            ComplianceFramework::NistCsf => "NIST Cybersecurity Framework",
            ComplianceFramework::Hipaa => "HIPAA Security Rule",
            ComplianceFramework::PciDss => "PCI DSS 4.0",
            ComplianceFramework::Fedramp => "FedRAMP Moderate",
            ComplianceFramework::Gdpr => "GDPR",
            ComplianceFramework::Ccjpa => "CCPA",
            ComplianceFramework::CisAws => "CIS AWS Foundations Benchmark",
            ComplianceFramework::CisAzure => "CIS Azure Foundations Benchmark",
            ComplianceFramework::CisGcp => "CIS GCP Foundations Benchmark",
            ComplianceFramework::CisKubernetes => "CIS Kubernetes Benchmark",
            ComplianceFramework::Hds => "HDS (Hébergement de Données de Santé)",
            ComplianceFramework::Bsi => "BSI C5",
        }
    }
}

/// =============================================================================
/// ENCRYPTION ENUMERATIONS
/// =============================================================================

/// Encryption types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EncryptionType {
    None,
    SseS3,
    SseKms,
    SseC,
    Tls,
    CustomerManaged,
    Hsm,
}

/// =============================================================================
/// ANALYSIS STATUS ENUMERATIONS
/// =============================================================================

/// Status of an analysis job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, ToSchema)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AnalysisStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Partial,
}

// End of enums.rs
