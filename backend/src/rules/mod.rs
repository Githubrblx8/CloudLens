//! Security Rules Module
//! 
//! This module contains the comprehensive security rule engine for CloudLens.
//! It implements over 250 security detection rules across multiple categories:
//! - IAM & Permissions
//! - Network Security
//! - Data Protection
//! - Compute Security
//! - Container Security
//! - Logging & Monitoring
//! - Compliance Rules

pub mod iam_rules;
pub mod network_rules;
pub mod data_protection_rules;
pub mod compute_rules;
pub mod container_rules;
pub mod logging_rules;
pub mod compliance_rules;
pub mod rule_engine;
pub mod rule_registry;

pub use iam_rules::*;
pub use network_rules::*;
pub use data_protection_rules::*;
pub use compute_rules::*;
pub use container_rules::*;
pub use logging_rules::*;
pub use compliance_rules::*;
pub use rule_engine::*;
pub use rule_registry::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_registry_initialization() {
        let registry = RuleRegistry::new();
        assert!(registry.get_all_rules().is_empty());
    }

    #[test]
    fn test_rule_engine_creation() {
        let engine = RuleEngine::new();
        assert_eq!(engine.get_rule_count(), 0);
    }
}
