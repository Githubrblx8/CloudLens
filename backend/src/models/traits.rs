//! CloudLens Trait Definitions
//! 
//! This module defines core traits used throughout the platform for
//! abstraction, polymorphism, and extensibility.

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use crate::models::{CloudResource, SecurityRisk, AnalysisReport};

/// =============================================================================
/// CONNECTOR TRAITS
/// =============================================================================

/// Trait for cloud provider connectors
#[async_trait]
pub trait CloudConnector: Send + Sync {
    /// Get the provider name
    fn provider_name(&self) -> &'static str;
    
    /// Authenticate with the cloud provider
    async fn authenticate(&self) -> Result<(), ConnectorError>;
    
    /// Fetch all resources from the provider
    async fn fetch_resources(&self) -> Result<Vec<CloudResource>, ConnectorError>;
    
    /// Fetch resources by type
    async fn fetch_resources_by_type(
        &self,
        resource_type: &str,
    ) -> Result<Vec<CloudResource>, ConnectorError>;
    
    /// Fetch IAM policies
    async fn fetch_iam_policies(&self) -> Result<Vec<serde_json::Value>, ConnectorError>;
    
    /// Fetch network configuration
    async fn fetch_network_config(&self) -> Result<serde_json::Value, ConnectorError>;
    
    /// Check connectivity
    async fn check_connectivity(&self) -> bool;
    
    /// Get supported resource types
    fn supported_resource_types(&self) -> Vec<&str>;
    
    /// Get rate limit information
    fn rate_limit_info(&self) -> RateLimitInfo;
}

/// Information about API rate limits
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_limit: u32,
}

/// Error type for connector operations
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("API error: {0}")]
    ApiError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Timeout error")]
    Timeout,
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// =============================================================================
/// ANALYZER TRAITS
/// =============================================================================

/// Trait for security analyzers
#[async_trait]
pub trait SecurityAnalyzer: Send + Sync {
    /// Get analyzer name
    fn name(&self) -> &'static str;
    
    /// Get analyzer description
    fn description(&self) -> &'static str;
    
    /// Get analyzer version
    fn version(&self) -> &'static str;
    
    /// Analyze a single resource
    async fn analyze_resource(
        &self,
        resource: &CloudResource,
    ) -> Result<Vec<SecurityRisk>, AnalyzerError>;
    
    /// Analyze multiple resources
    async fn analyze_resources(
        &self,
        resources: &[CloudResource],
    ) -> Result<Vec<SecurityRisk>, AnalyzerError>;
    
    /// Get supported resource types
    fn supported_resource_types(&self) -> Vec<&str>;
    
    /// Check if analyzer is enabled
    fn is_enabled(&self) -> bool;
    
    /// Get analyzer configuration
    fn configuration(&self) -> HashMap<String, serde_json::Value>;
}

/// Error type for analyzer operations
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// =============================================================================
/// RULE ENGINE TRAITS
/// =============================================================================

/// Trait for security rules
pub trait SecurityRule: Send + Sync {
    /// Get rule ID
    fn rule_id(&self) -> &'static str;
    
    /// Get rule name
    fn rule_name(&self) -> &'static str;
    
    /// Get rule description
    fn rule_description(&self) -> &'static str;
    
    /// Get rule severity
    fn rule_severity(&self) -> crate::models::RiskSeverity;
    
    /// Get rule category
    fn rule_category(&self) -> crate::models::RiskCategory;
    
    /// Check if rule applies to resource
    fn applies_to(&self, resource: &CloudResource) -> bool;
    
    /// Evaluate rule on resource
    fn evaluate(&self, resource: &CloudResource) -> RuleEvaluationResult;
    
    /// Get remediation steps
    fn get_remediation(&self) -> Vec<String>;
    
    /// Get related CWE IDs
    fn cwe_ids(&self) -> Vec<&str>;
    
    /// Get related MITRE ATT&CK IDs
    fn mitre_ids(&self) -> Vec<&str>;
}

/// Result of rule evaluation
#[derive(Debug, Clone)]
pub struct RuleEvaluationResult {
    pub passed: bool,
    pub message: String,
    pub evidence: Vec<String>,
    pub risk_score: u8,
}

/// =============================================================================
/// GRAPH TRAITS
/// =============================================================================

/// Trait for graph builders
pub trait GraphBuilder: Send + Sync {
    /// Build graph from resources
    fn build_graph(&self, resources: &[CloudResource]) -> crate::models::ResourceGraph;
    
    /// Add resource to graph
    fn add_resource(&mut self, resource: &CloudResource);
    
    /// Remove resource from graph
    fn remove_resource(&mut self, resource_id: &str);
    
    /// Add edge between resources
    fn add_edge(&mut self, source: &str, target: &str, edge_type: &str);
    
    /// Get node count
    fn node_count(&self) -> usize;
    
    /// Get edge count
    fn edge_count(&self) -> usize;
}

/// Trait for path finding algorithms
pub trait PathFinder: Send + Sync {
    /// Find all paths between two nodes
    fn find_all_paths(&self, source: &str, target: &str) -> Vec<Vec<String>>;
    
    /// Find shortest path
    fn find_shortest_path(&self, source: &str, target: &str) -> Option<Vec<String>>;
    
    /// Find all attack paths
    fn find_attack_paths(&self) -> Vec<crate::models::AccessPath>;
    
    /// Find privilege escalation paths
    fn find_privilege_escalation_paths(&self) -> Vec<crate::models::AccessPath>;
    
    /// Find lateral movement paths
    fn find_lateral_movement_paths(&self) -> Vec<crate::models::AccessPath>;
}

/// =============================================================================
/// STORAGE TRAITS
/// =============================================================================

/// Trait for data storage backends
#[async_trait]
pub trait DataStorage: Send + Sync {
    /// Initialize storage
    async fn initialize(&self) -> Result<(), StorageError>;
    
    /// Store resources
    async fn store_resources(&self, resources: &[CloudResource]) -> Result<(), StorageError>;
    
    /// Get resources by ID
    async fn get_resource(&self, id: &str) -> Result<Option<CloudResource>, StorageError>;
    
    /// Get all resources
    async fn get_all_resources(&self) -> Result<Vec<CloudResource>, StorageError>;
    
    /// Store risks
    async fn store_risks(&self, risks: &[SecurityRisk]) -> Result<(), StorageError>;
    
    /// Get risks by severity
    async fn get_risks_by_severity(
        &self,
        severity: crate::models::RiskSeverity,
    ) -> Result<Vec<SecurityRisk>, StorageError>;
    
    /// Store analysis report
    async fn store_report(&self, report: &AnalysisReport) -> Result<(), StorageError>;
    
    /// Get latest report
    async fn get_latest_report(&self) -> Result<Option<AnalysisReport>, StorageError>;
    
    /// Delete resources
    async fn delete_resources(&self, ids: &[&str]) -> Result<(), StorageError>;
    
    /// Clear all data
    async fn clear_all(&self) -> Result<(), StorageError>;
}

/// Error type for storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Query failed: {0}")]
    QueryFailed(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Migration error: {0}")]
    MigrationError(String),
}

/// =============================================================================
/// REPORT GENERATOR TRAITS
/// =============================================================================

/// Trait for report generators
pub trait ReportGenerator: Send + Sync {
    /// Get generator name
    fn name(&self) -> &'static str;
    
    /// Get supported formats
    fn supported_formats(&self) -> Vec<&str>;
    
    /// Generate report in specified format
    fn generate_report(
        &self,
        report: &AnalysisReport,
        format: &str,
    ) -> Result<Vec<u8>, ReportError>;
    
    /// Export report to file
    fn export_to_file(
        &self,
        report: &AnalysisReport,
        path: &str,
        format: &str,
    ) -> Result<(), ReportError>;
}

/// Error type for report generation
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    
    #[error("Generation failed: {0}")]
    GenerationFailed(String),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Template error: {0}")]
    TemplateError(String),
}

/// =============================================================================
/// NOTIFICATION TRAITS
/// =============================================================================

/// Trait for notification channels
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Get channel name
    fn channel_name(&self) -> &'static str;
    
    /// Send notification
    async fn send_notification(
        &self,
        title: &str,
        message: &str,
        severity: crate::models::RiskSeverity,
    ) -> Result<(), NotificationError>;
    
    /// Send risk alert
    async fn send_risk_alert(
        &self,
        risk: &SecurityRisk,
    ) -> Result<(), NotificationError>;
    
    /// Check if channel is enabled
    fn is_enabled(&self) -> bool;
}

/// Error type for notifications
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Send failed: {0}")]
    SendFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// =============================================================================
/// PLUGIN TRAITS
/// =============================================================================

/// Trait for plugins
pub trait Plugin: Send + Sync {
    /// Get plugin name
    fn name(&self) -> &'static str;
    
    /// Get plugin version
    fn version(&self) -> &'static str;
    
    /// Get plugin description
    fn description(&self) -> &'static str;
    
    /// Get plugin author
    fn author(&self) -> &'static str;
    
    /// Initialize plugin
    fn initialize(&mut self) -> Result<(), PluginError>;
    
    /// Shutdown plugin
    fn shutdown(&mut self);
    
    /// Get plugin capabilities
    fn capabilities(&self) -> Vec<PluginCapability>;
}

/// Plugin capability types
#[derive(Debug, Clone, Copy)]
pub enum PluginCapability {
    ResourceDiscovery,
    RiskDetection,
    ComplianceChecking,
    ReportGeneration,
    Notification,
    DataExport,
    CustomAnalysis,
}

/// Error type for plugin operations
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Dependency missing: {0}")]
    DependencyMissing(String),
    
    #[error("Incompatible version: {0}")]
    IncompatibleVersion(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

// End of traits.rs
