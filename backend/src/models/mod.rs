//! CloudGhidra Core Data Models
//! 
//! This module contains all the data structures used throughout the CloudGhidra platform.
//! It provides comprehensive type definitions for cloud resources, security risks,
//! IAM policies, graph structures, and analysis results.

pub mod enums;
pub mod structs;
pub mod traits;
pub mod types;

pub use enums::*;
pub use structs::*;
pub use traits::*;
pub use types::*;

// Re-export commonly used types for convenience
pub use crate::models::enums::{
    CloudProvider,
    ResourceType,
    RiskSeverity,
    RiskCategory,
    RiskStatus,
    IamAction,
    IamEffect,
    ConnectionType,
    AnalysisStatus,
    ComplianceFramework,
    EncryptionType,
    NetworkVisibility,
    AccessLevel,
};

pub use crate::models::structs::{
    CloudResource,
    SecurityRisk,
    AccessPath,
    IamPolicy,
    IamStatement,
    ResourceGraph,
    AnalysisReport,
    Recommendation,
    CloudAccount,
    ResourceMetadata,
    NetworkConfiguration,
    Tag,
    Finding,
    Remediation,
};
