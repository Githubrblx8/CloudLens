//! CloudLens Core Data Structures
//! 
//! This module defines the main data structures used throughout the platform,
//! including resources, risks, policies, and analysis results.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;
use petgraph::graph::DiGraph;
use crate::models::enums::*;

/// =============================================================================
/// CORE RESOURCE STRUCTURES
/// =============================================================================

/// Represents any cloud resource in the infrastructure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    /// Unique identifier for this resource
    pub id: String,
    
    /// Human-readable name
    pub name: String,
    
    /// ARN or equivalent unique identifier from cloud provider
    pub arn: Option<String>,
    
    /// Type of resource
    pub resource_type: ResourceType,
    
    /// Cloud provider
    pub provider: CloudProvider,
    
    /// Region/Location
    pub region: Option<String>,
    
    /// Account ID or project ID
    pub account_id: Option<String>,
    
    /// Resource metadata
    pub metadata: ResourceMetadata,
    
    /// Network configuration
    pub network_config: Option<NetworkConfiguration>,
    
    /// Tags/Labels
    pub tags: Vec<Tag>,
    
    /// Associated IAM roles/policies
    pub iam_attachments: Vec<String>,
    
    /// Parent resource ID (for hierarchical resources)
    pub parent_id: Option<String>,
    
    /// Child resource IDs
    pub child_ids: Vec<String>,
    
    /// Dependencies on other resources
    pub dependencies: Vec<String>,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
    
    /// Whether resource is active
    pub is_active: bool,
    
    /// Custom properties specific to resource type
    pub properties: HashMap<String, serde_json::Value>,
}

impl CloudResource {
    /// Create a new cloud resource
    pub fn new(
        name: String,
        resource_type: ResourceType,
        provider: CloudProvider,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            arn: None,
            resource_type,
            provider,
            region: None,
            account_id: None,
            metadata: ResourceMetadata::default(),
            network_config: None,
            tags: Vec::new(),
            iam_attachments: Vec::new(),
            parent_id: None,
            child_ids: Vec::new(),
            dependencies: Vec::new(),
            created_at: now,
            updated_at: now,
            is_active: true,
            properties: HashMap::new(),
        }
    }
    
    /// Check if resource is publicly accessible
    pub fn is_public(&self) -> bool {
        self.network_config
            .as_ref()
            .map(|nc| nc.visibility == NetworkVisibility::Public)
            .unwrap_or(false)
    }
    
    /// Check if resource has encryption enabled
    pub fn is_encrypted(&self) -> bool {
        self.metadata.encryption_type != EncryptionType::None
    }
    
    /// Get risk score based on configuration
    pub fn base_risk_score(&self) -> u8 {
        let mut score = 0u8;
        
        // Public exposure adds risk
        if self.is_public() {
            score += 30;
        }
        
        // Lack of encryption adds risk
        if !self.is_encrypted() {
            score += 20;
        }
        
        // Many IAM attachments can indicate complexity
        if self.iam_attachments.len() > 3 {
            score += 10;
        }
        
        score.min(100)
    }
}

/// Metadata for a cloud resource
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMetadata {
    /// Description of the resource
    pub description: Option<String>,
    
    /// Owner or team responsible
    pub owner: Option<String>,
    
    /// Environment (prod, staging, dev, etc.)
    pub environment: Option<String>,
    
    /// Cost center
    pub cost_center: Option<String>,
    
    /// Compliance requirements
    pub compliance_frameworks: Vec<ComplianceFramework>,
    
    /// Encryption type in use
    pub encryption_type: EncryptionType,
    
    /// Backup configuration
    pub backup_enabled: bool,
    
    /// Versioning enabled (for storage)
    pub versioning_enabled: bool,
    
    /// Logging enabled
    pub logging_enabled: bool,
    
    /// Monitoring enabled
    pub monitoring_enabled: bool,
    
    /// Auto-scaling enabled
    pub auto_scaling_enabled: bool,
    
    /// High availability configuration
    pub high_availability: bool,
    
    /// Disaster recovery configuration
    pub disaster_recovery: bool,
    
    /// Data classification
    pub data_classification: Option<String>,
    
    /// Retention policy
    pub retention_days: Option<u32>,
    
    /// Custom attributes
    pub custom_attributes: HashMap<String, String>,
}

/// Network configuration for a resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfiguration {
    /// Visibility level
    pub visibility: NetworkVisibility,
    
    /// VPC or network ID
    pub vpc_id: Option<String>,
    
    /// Subnet IDs
    pub subnet_ids: Vec<String>,
    
    /// Security group IDs
    pub security_group_ids: Vec<String>,
    
    /// Public IP address
    pub public_ip: Option<String>,
    
    /// Private IP address
    pub private_ip: Option<String>,
    
    /// DNS name
    pub dns_name: Option<String>,
    
    /// Port configurations
    pub open_ports: Vec<PortConfiguration>,
    
    /// Inbound rules summary
    pub inbound_rules_count: usize,
    
    /// Outbound rules summary
    pub outbound_rules_count: usize,
    
    /// NAT gateway attached
    pub nat_gateway: bool,
    
    /// Internet gateway attached
    pub internet_gateway: bool,
    
    /// VPC peering connections
    pub peering_connections: Vec<String>,
    
    /// Load balancer attached
    pub load_balancer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortConfiguration {
    pub port: u16,
    pub protocol: String,
    pub source: String,
    pub description: Option<String>,
}

/// Tag for resource organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

/// =============================================================================
/// SECURITY RISK STRUCTURES
/// =============================================================================

/// Represents a detected security risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRisk {
    /// Unique identifier
    pub id: String,
    
    /// Risk title
    pub title: String,
    
    /// Detailed description
    pub description: String,
    
    /// Severity level
    pub severity: RiskSeverity,
    
    /// Risk category
    pub category: RiskCategory,
    
    /// Current status
    pub status: RiskStatus,
    
    /// Affected resource IDs
    pub affected_resources: Vec<String>,
    
    /// CWE identifier if applicable
    pub cwe_id: Option<String>,
    
    /// MITRE ATT&CK technique ID
    pub mitre_technique_id: Option<String>,
    
    /// CVSS score if applicable
    pub cvss_score: Option<f32>,
    
    /// First detected timestamp
    pub first_detected: DateTime<Utc>,
    
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    
    /// Risk score (0-100)
    pub risk_score: u8,
    
    /// Exploitability score
    pub exploitability_score: u8,
    
    /// Impact score
    pub impact_score: u8,
    
    /// Remediation steps
    pub remediation: Vec<Remediation>,
    
    /// Evidence supporting the finding
    pub evidence: Vec<String>,
    
    /// Related risks
    pub related_risks: Vec<String>,
    
    /// Attack paths that include this risk
    pub attack_paths: Vec<String>,
    
    /// Compliance violations
    pub compliance_violations: Vec<ComplianceViolation>,
    
    /// False positive likelihood (0-1)
    pub false_positive_likelihood: f32,
    
    /// Business context
    pub business_context: Option<String>,
    
    /// Recommended SLA for remediation
    pub recommended_sla: String,
}

impl SecurityRisk {
    /// Create a new security risk
    pub fn new(
        title: String,
        description: String,
        severity: RiskSeverity,
        category: RiskCategory,
    ) -> Self {
        let now = Utc::now();
        let risk_score = severity.score();
        
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            description,
            severity,
            category,
            status: RiskStatus::New,
            affected_resources: Vec::new(),
            cwe_id: None,
            mitre_technique_id: None,
            cvss_score: None,
            first_detected: now,
            last_seen: now,
            risk_score,
            exploitability_score: 50,
            impact_score: risk_score,
            remediation: Vec::new(),
            evidence: Vec::new(),
            related_risks: Vec::new(),
            attack_paths: Vec::new(),
            compliance_violations: Vec::new(),
            false_positive_likelihood: 0.1,
            business_context: None,
            recommended_sla: severity.remediation_sla().to_string(),
        }
    }
    
    /// Calculate overall risk score
    pub fn calculate_risk_score(&mut self) {
        self.risk_score = (
            (self.severity.score() as u32 * 40 +
             self.exploitability_score as u32 * 30 +
             self.impact_score as u32 * 30) / 100
        ) as u8;
    }
}

/// Remediation step for a risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    /// Step description
    pub description: String,
    
    /// Priority order
    pub priority: u32,
    
    /// Estimated effort (in hours)
    pub estimated_effort_hours: Option<f32>,
    
    /// Required permissions
    pub required_permissions: Vec<String>,
    
    /// CLI commands (if applicable)
    pub cli_commands: Vec<String>,
    
    /// Console steps (if applicable)
    pub console_steps: Vec<String>,
    
    /// Terraform snippet (if applicable)
    pub terraform_snippet: Option<String>,
    
    /// CloudFormation snippet (if applicable)
    pub cloudformation_snippet: Option<String>,
    
    /// Documentation links
    pub documentation_links: Vec<String>,
    
    /// Automated fix available
    pub automated_fix_available: bool,
    
    /// Rollback instructions
    pub rollback_instructions: Option<String>,
}

/// Compliance violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub control_name: String,
    pub requirement: String,
    pub violation_details: String,
}

/// =============================================================================
/// IAM STRUCTURES
/// =============================================================================

/// IAM Policy document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicy {
    /// Policy ID
    pub id: String,
    
    /// Policy name
    pub name: String,
    
    /// Policy ARN
    pub arn: String,
    
    /// Provider
    pub provider: CloudProvider,
    
    /// Policy version
    pub version: String,
    
    /// Policy document
    pub document: PolicyDocument,
    
    /// Attached to users
    pub attached_users: Vec<String>,
    
    /// Attached to groups
    pub attached_groups: Vec<String>,
    
    /// Attached to roles
    pub attached_roles: Vec<String>,
    
    /// Is managed policy
    pub is_managed: bool,
    
    /// Creation date
    pub created_at: DateTime<Utc>,
    
    /// Last updated
    pub updated_at: DateTime<Utc>,
    
    /// Usage count
    pub usage_count: usize,
    
    /// Analysis results
    pub analysis: PolicyAnalysis,
}

/// IAM Policy document structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: String,
    pub statements: Vec<IamStatement>,
}

/// IAM Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamStatement {
    /// Effect (Allow/Deny)
    pub effect: IamEffect,
    
    /// Actions
    pub actions: Vec<String>,
    
    /// Not actions
    pub not_actions: Vec<String>,
    
    /// Resources
    pub resources: Vec<String>,
    
    /// Not resources
    pub not_resources: Vec<String>,
    
    /// Conditions
    pub conditions: Vec<Condition>,
    
    /// Sid (statement ID)
    pub sid: Option<String>,
    
    /// Principal (for trust policies)
    pub principal: Option<Principal>,
    
    /// Not principal
    pub not_principal: Option<Principal>,
}

/// Condition in IAM policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub operator: String,
    pub key: String,
    pub values: Vec<String>,
}

/// Principal in IAM policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub aws: Option<Vec<String>>,
    pub service: Option<Vec<String>>,
    pub federated: Option<Vec<String>>,
}

/// Analysis results for an IAM policy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyAnalysis {
    /// Has wildcard actions
    pub has_wildcard_actions: bool,
    
    /// Has wildcard resources
    pub has_wildcard_resources: bool,
    
    /// Has dangerous permissions
    pub has_dangerous_permissions: bool,
    
    /// Dangerous permission list
    pub dangerous_permissions: Vec<String>,
    
    /// Privilege escalation potential
    pub privilege_escalation_potential: bool,
    
    /// Data exfiltration potential
    pub data_exfiltration_potential: bool,
    
    /// Lateral movement potential
    pub lateral_movement_potential: bool,
    
    /// Access level summary
    pub access_level_summary: HashMap<String, AccessLevel>,
    
    /// Risk score
    pub risk_score: u8,
    
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// =============================================================================
/// GRAPH STRUCTURES
/// =============================================================================

/// Resource graph representing infrastructure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGraph {
    /// Graph ID
    pub id: String,
    
    /// Graph name
    pub name: String,
    
    /// Number of nodes
    pub node_count: usize,
    
    /// Number of edges
    pub edge_count: usize,
    
    /// Serialized graph data
    pub graph_data: GraphData,
    
    /// Connected components
    pub connected_components: usize,
    
    /// Critical paths identified
    pub critical_paths: Vec<CriticalPath>,
    
    /// Attack surface analysis
    pub attack_surface: AttackSurfaceAnalysis,
    
    /// Created at
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphData {
    /// Nodes with their properties
    pub nodes: Vec<GraphNode>,
    /// Edges with their properties
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: String,
    pub label: String,
    pub properties: HashMap<String, serde_json::Value>,
    pub risk_score: u8,
    pub is_critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: String,
    pub label: Option<String>,
    pub properties: HashMap<String, serde_json::Value>,
}

/// Critical path in the infrastructure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPath {
    /// Path ID
    pub id: String,
    
    /// Path name
    pub name: String,
    
    /// Path type
    pub path_type: PathType,
    
    /// Nodes in the path
    pub nodes: Vec<String>,
    
    /// Edges in the path
    pub edges: Vec<(String, String, String)>,
    
    /// Total risk score
    pub total_risk_score: u8,
    
    /// Description
    pub description: String,
    
    /// Mitigation suggestions
    pub mitigations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathType {
    AttackPath,
    DataAccessPath,
    PrivilegeEscalationPath,
    LateralMovementPath,
    DependencyPath,
    NetworkPath,
}

/// Attack surface analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackSurfaceAnalysis {
    /// Public-facing resources
    pub public_facing_resources: Vec<String>,
    
    /// Internet-exposed ports
    pub exposed_ports: Vec<u16>,
    
    /// Entry points
    pub entry_points: Vec<String>,
    
    /// High-value targets
    pub high_value_targets: Vec<String>,
    
    /// Weak authentication points
    pub weak_auth_points: Vec<String>,
    
    /// Overall attack surface score
    pub surface_score: u8,
}

/// Access path representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPath {
    /// Path ID
    pub id: String,
    
    /// Source entity
    pub source: String,
    
    /// Target resource
    pub target: String,
    
    /// Path steps
    pub steps: Vec<AccessPathStep>,
    
    /// Permissions granted along path
    pub permissions: Vec<String>,
    
    /// Risk level
    pub risk_level: RiskSeverity,
    
    /// Is exploitable
    pub is_exploitable: bool,
    
    /// Exploitation difficulty
    pub exploitation_difficulty: String,
    
    /// Detection methods
    pub detection_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPathStep {
    pub step_number: usize,
    pub action: String,
    pub resource: String,
    pub permission_used: String,
    pub condition: Option<String>,
}

/// =============================================================================
/// ANALYSIS REPORT STRUCTURES
/// =============================================================================

/// Complete analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Report ID
    pub id: String,
    
    /// Report name
    pub name: String,
    
    /// Analysis status
    pub status: AnalysisStatus,
    
    /// Start time
    pub started_at: DateTime<Utc>,
    
    /// End time
    pub completed_at: Option<DateTime<Utc>>,
    
    /// Duration in seconds
    pub duration_seconds: Option<f64>,
    
    /// Summary statistics
    pub summary: AnalysisSummary,
    
    /// Detected risks
    pub risks: Vec<SecurityRisk>,
    
    /// Analyzed resources
    pub resources: Vec<CloudResource>,
    
    /// IAM analysis
    pub iam_analysis: IamAnalysisResult,
    
    /// Network analysis
    pub network_analysis: NetworkAnalysisResult,
    
    /// Compliance analysis
    pub compliance_analysis: ComplianceAnalysisResult,
    
    /// Graph analysis
    pub graph_analysis: GraphAnalysisResult,
    
    /// Recommendations
    pub recommendations: Vec<Recommendation>,
    
    /// Executive summary
    pub executive_summary: String,
    
    /// Technical details
    pub technical_details: String,
    
    /// Export formats available
    pub available_exports: Vec<String>,
}

/// Analysis summary statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Total resources analyzed
    pub total_resources: usize,
    
    /// Resources by type
    pub resources_by_type: HashMap<String, usize>,
    
    /// Resources by provider
    pub resources_by_provider: HashMap<String, usize>,
    
    /// Total risks found
    pub total_risks: usize,
    
    /// Risks by severity
    pub risks_by_severity: HashMap<String, usize>,
    
    /// Risks by category
    pub risks_by_category: HashMap<String, usize>,
    
    /// Critical risks count
    pub critical_risks: usize,
    
    /// High risks count
    pub high_risks: usize,
    
    /// Medium risks count
    pub medium_risks: usize,
    
    /// Low risks count
    pub low_risks: usize,
    
    /// Overall security score (0-100)
    pub overall_security_score: u8,
    
    /// Attack surface score
    pub attack_surface_score: u8,
    
    /// IAM security score
    pub iam_security_score: u8,
    
    /// Network security score
    pub network_security_score: u8,
    
    /// Data protection score
    pub data_protection_score: u8,
    
    /// Compliance score
    pub compliance_score: u8,
}

/// Recommendation for improvement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Recommendation ID
    pub id: String,
    
    /// Title
    pub title: String,
    
    /// Description
    pub description: String,
    
    /// Priority
    pub priority: u8,
    
    /// Category
    pub category: String,
    
    /// Related risks
    pub related_risks: Vec<String>,
    
    /// Effort required
    pub effort: String,
    
    /// Impact
    pub impact: String,
    
    /// Implementation steps
    pub steps: Vec<String>,
    
    /// Expected outcome
    pub expected_outcome: String,
}

/// IAM analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IamAnalysisResult {
    /// Total identities
    pub total_identities: usize,
    
    /// Total roles
    pub total_roles: usize,
    
    /// Total policies
    pub total_policies: usize,
    
    /// Overly permissive identities
    pub overly_permissive: Vec<String>,
    
    /// Unused permissions
    pub unused_permissions: Vec<String>,
    
    /// Privilege escalation paths
    pub privilege_escalation_paths: Vec<AccessPath>,
    
    /// Cross-account trusts
    pub cross_account_trusts: Vec<String>,
    
    /// External principals
    pub external_principals: Vec<String>,
    
    /// MFA status
    pub mfa_enabled_count: usize,
    pub mfa_disabled_count: usize,
    
    /// Access keys analysis
    pub active_access_keys: usize,
    pub unused_access_keys: usize,
    pub old_access_keys: usize,
}

/// Network analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkAnalysisResult {
    /// Total networks/VPCs
    pub total_networks: usize,
    
    /// Public subnets
    pub public_subnets: usize,
    
    /// Private subnets
    pub private_subnets: usize,
    
    /// Open security groups
    pub open_security_groups: Vec<String>,
    
    /// Publicly accessible resources
    pub publicly_accessible: Vec<String>,
    
    /// Missing security groups
    pub missing_security_groups: Vec<String>,
    
    /// Unrestricted ingress rules
    pub unrestricted_ingress: Vec<String>,
    
    /// Unrestricted egress rules
    pub unrestricted_egress: Vec<String>,
    
    /// Peering connections
    pub peering_connections: usize,
    
    /// Transit gateways
    pub transit_gateways: usize,
}

/// Compliance analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceAnalysisResult {
    /// Frameworks checked
    pub frameworks_checked: Vec<String>,
    
    /// Total controls
    pub total_controls: usize,
    
    /// Passed controls
    pub passed_controls: usize,
    
    /// Failed controls
    pub failed_controls: usize,
    
    /// Not applicable controls
    pub na_controls: usize,
    
    /// Violations by framework
    pub violations_by_framework: HashMap<String, Vec<ComplianceViolation>>,
    
    /// Compliance percentage by framework
    pub compliance_percentage: HashMap<String, f32>,
}

/// Graph analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphAnalysisResult {
    /// Total nodes
    pub total_nodes: usize,
    
    /// Total edges
    pub total_edges: usize,
    
    /// Connected components
    pub connected_components: usize,
    
    /// Critical nodes
    pub critical_nodes: Vec<String>,
    
    /// Bridge edges
    pub bridge_edges: Vec<(String, String)>,
    
    /// Attack paths found
    pub attack_paths_count: usize,
    
    /// Privilege escalation paths
    pub privilege_escalation_paths_count: usize,
    
    /// Average path length
    pub average_path_length: f32,
    
    /// Graph density
    pub density: f32,
}

/// =============================================================================
/// CLOUD ACCOUNT STRUCTURES
/// =============================================================================

/// Cloud account representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAccount {
    /// Account ID
    pub id: String,
    
    /// Account name
    pub name: String,
    
    /// Provider
    pub provider: CloudProvider,
    
    /// Account number/ID from provider
    pub provider_account_id: String,
    
    /// Organization ID
    pub organization_id: Option<String>,
    
    /// Account status
    pub status: String,
    
    /// Connection method
    pub connection_method: ConnectionMethod,
    
    /// Last synced
    pub last_synced: Option<DateTime<Utc>>,
    
    /// Sync status
    pub sync_status: SyncStatus,
    
    /// Resource count
    pub resource_count: usize,
    
    /// Enabled services
    pub enabled_services: Vec<String>,
    
    /// Regions scanned
    pub regions_scanned: Vec<String>,
    
    /// Excluded resources
    pub excluded_resources: Vec<String>,
    
    /// Custom configuration
    pub configuration: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionMethod {
    RoleAssumption,
    AccessKey,
    ServicePrincipal,
    WorkloadIdentity,
    ApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStatus {
    NeverSynced,
    Syncing,
    Synced,
    PartialSync,
    Failed,
    Error,
}

/// =============================================================================
/// FINDING STRUCTURES
/// =============================================================================

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Finding ID
    pub id: String,
    
    /// Finding title
    pub title: String,
    
    /// Description
    pub description: String,
    
    /// Severity
    pub severity: RiskSeverity,
    
    /// Finding type
    pub finding_type: String,
    
    /// Affected resources
    pub affected_resources: Vec<String>,
    
    /// Evidence
    pub evidence: Vec<FindingEvidence>,
    
    /// First seen
    pub first_seen: DateTime<Utc>,
    
    /// Last seen
    pub last_seen: DateTime<Utc>,
    
    /// State
    pub state: FindingState,
    
    /// Confidence score (0-100)
    pub confidence: u8,
    
    /// Source of finding
    pub source: String,
    
    /// Raw finding data
    pub raw_finding: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub evidence_type: String,
    pub value: String,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingState {
    New,
    Active,
    Resolved,
    FalsePositive,
    Suppressed,
    Archived,
}

// End of structs.rs
