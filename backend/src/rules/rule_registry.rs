//! Rule Registry - Central repository for all security rules
//! 
//! This module provides a centralized registry for managing, organizing,
//! and retrieving security rules. It supports dynamic rule loading,
//! categorization, and filtering.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use crate::models::traits::SecurityRule;
use crate::models::{SecurityRisk, RiskSeverity, RiskCategory, CloudResource};

/// Unique identifier for a rule
pub type RuleId = String;

/// Category identifier
pub type CategoryId = String;

/// Metadata about a security rule
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub id: RuleId,
    pub name: String,
    pub description: String,
    pub category: RiskCategory,
    pub severity: RiskSeverity,
    pub cwe_id: Option<String>,
    pub mitre_attack_id: Option<String>,
    pub compliance_frameworks: Vec<String>,
    pub tags: Vec<String>,
    pub version: String,
    pub author: String,
    pub enabled: bool,
    pub auto_remediation_available: bool,
}

impl RuleMetadata {
    pub fn new(id: &str, name: &str, description: &str, category: RiskCategory, severity: RiskSeverity) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category,
            severity,
            cwe_id: None,
            mitre_attack_id: None,
            compliance_frameworks: Vec::new(),
            tags: Vec::new(),
            version: "1.0.0".to_string(),
            author: "CloudGhidra".to_string(),
            enabled: true,
            auto_remediation_available: false,
        }
    }

    pub fn with_cwe(mut self, cwe_id: &str) -> Self {
        self.cwe_id = Some(cwe_id.to_string());
        self
    }

    pub fn with_mitre(mut self, mitre_id: &str) -> Self {
        self.mitre_attack_id = Some(mitre_id.to_string());
        self
    }

    pub fn with_compliance(mut self, frameworks: Vec<&str>) -> Self {
        self.compliance_frameworks = frameworks.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_auto_remediation(mut self, available: bool) -> Self {
        self.auto_remediation_available = available;
        self
    }
}

/// Central registry for all security rules
pub struct RuleRegistry {
    rules: HashMap<RuleId, Arc<dyn SecurityRule + Send + Sync>>,
    metadata: HashMap<RuleId, RuleMetadata>,
    categories: HashMap<CategoryId, HashSet<RuleId>>,
    tags: HashMap<String, HashSet<RuleId>>,
    enabled_rules: HashSet<RuleId>,
}

impl RuleRegistry {
    /// Create a new empty rule registry
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            metadata: HashMap::new(),
            categories: HashMap::new(),
            tags: HashMap::new(),
            enabled_rules: HashSet::new(),
        }
    }

    /// Register a new security rule
    pub fn register<R: SecurityRule + Send + Sync + 'static>(&mut self, rule: R, metadata: RuleMetadata) {
        let rule_id = metadata.id.clone();
        
        // Store the rule
        self.rules.insert(rule_id.clone(), Arc::new(rule));
        self.metadata.insert(rule_id.clone(), metadata.clone());
        
        // Index by category
        let category_key = format!("{:?}", metadata.category);
        self.categories
            .entry(category_key)
            .or_insert_with(HashSet::new)
            .insert(rule_id.clone());
        
        // Index by tags
        for tag in &metadata.tags {
            self.tags
                .entry(tag.clone())
                .or_insert_with(HashSet::new)
                .insert(rule_id.clone());
        }
        
        // Add to enabled rules if enabled
        if metadata.enabled {
            self.enabled_rules.insert(rule_id);
        }
    }

    /// Get a rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<Arc<dyn SecurityRule + Send + Sync>> {
        self.rules.get(rule_id).cloned()
    }

    /// Get metadata for a rule
    pub fn get_metadata(&self, rule_id: &str) -> Option<&RuleMetadata> {
        self.metadata.get(rule_id)
    }

    /// Get all rules in a category
    pub fn get_rules_by_category(&self, category: &RiskCategory) -> Vec<Arc<dyn SecurityRule + Send + Sync>> {
        let category_key = format!("{:?}", category);
        if let Some(rule_ids) = self.categories.get(&category_key) {
            rule_ids
                .iter()
                .filter_map(|id| self.rules.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all rules with a specific tag
    pub fn get_rules_by_tag(&self, tag: &str) -> Vec<Arc<dyn SecurityRule + Send + Sync>> {
        if let Some(rule_ids) = self.tags.get(tag) {
            rule_ids
                .iter()
                .filter_map(|id| self.rules.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all enabled rules
    pub fn get_enabled_rules(&self) -> Vec<Arc<dyn SecurityRule + Send + Sync>> {
        self.enabled_rules
            .iter()
            .filter_map(|id| self.rules.get(id).cloned())
            .collect()
    }

    /// Get all rules (enabled and disabled)
    pub fn get_all_rules(&self) -> Vec<Arc<dyn SecurityRule + Send + Sync>> {
        self.rules.values().cloned().collect()
    }

    /// Get all rule metadata
    pub fn get_all_metadata(&self) -> Vec<&RuleMetadata> {
        self.metadata.values().collect()
    }

    /// Enable a rule
    pub fn enable_rule(&mut self, rule_id: &str) -> bool {
        if self.rules.contains_key(rule_id) {
            self.enabled_rules.insert(rule_id.to_string());
            if let Some(meta) = self.metadata.get_mut(rule_id) {
                meta.enabled = true;
            }
            true
        } else {
            false
        }
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, rule_id: &str) -> bool {
        if self.rules.contains_key(rule_id) {
            self.enabled_rules.remove(rule_id);
            if let Some(meta) = self.metadata.get_mut(rule_id) {
                meta.enabled = false;
            }
            true
        } else {
            false
        }
    }

    /// Get statistics about the registry
    pub fn get_statistics(&self) -> RegistryStatistics {
        let total_rules = self.rules.len();
        let enabled_rules = self.enabled_rules.len();
        let disabled_rules = total_rules - enabled_rules;
        
        let mut rules_by_category: HashMap<String, usize> = HashMap::new();
        for (category, rule_ids) in &self.categories {
            rules_by_category.insert(category.clone(), rule_ids.len());
        }
        
        let mut rules_by_severity: HashMap<String, usize> = HashMap::new();
        for meta in self.metadata.values() {
            let severity_key = format!("{:?}", meta.severity);
            *rules_by_severity.entry(severity_key).or_insert(0) += 1;
        }
        
        RegistryStatistics {
            total_rules,
            enabled_rules,
            disabled_rules,
            rules_by_category,
            rules_by_severity,
            total_categories: self.categories.len(),
            total_tags: self.tags.len(),
        }
    }

    /// Search rules by keyword
    pub fn search_rules(&self, keyword: &str) -> Vec<&RuleMetadata> {
        let keyword_lower = keyword.to_lowercase();
        self.metadata
            .values()
            .filter(|meta| {
                meta.name.to_lowercase().contains(&keyword_lower)
                    || meta.description.to_lowercase().contains(&keyword_lower)
                    || meta.tags.iter().any(|t| t.to_lowercase().contains(&keyword_lower))
            })
            .collect()
    }

    /// Get rules by compliance framework
    pub fn get_rules_by_compliance(&self, framework: &str) -> Vec<Arc<dyn SecurityRule + Send + Sync>> {
        let framework_upper = framework.to_uppercase();
        self.metadata
            .iter()
            .filter(|(_, meta)| meta.compliance_frameworks.iter().any(|f| f == &framework_upper))
            .filter_map(|(id, _)| self.rules.get(id).cloned())
            .collect()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the rule registry
#[derive(Debug, Clone)]
pub struct RegistryStatistics {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub disabled_rules: usize,
    pub rules_by_category: HashMap<String, usize>,
    pub rules_by_severity: HashMap<String, usize>,
    pub total_categories: usize,
    pub total_tags: usize,
}

impl RegistryStatistics {
    pub fn print_report(&self) {
        println!("=== Rule Registry Statistics ===");
        println!("Total Rules: {}", self.total_rules);
        println!("Enabled Rules: {}", self.enabled_rules);
        println!("Disabled Rules: {}", self.disabled_rules);
        println!("Total Categories: {}", self.total_categories);
        println!("Total Tags: {}", self.total_tags);
        
        println!("\nRules by Category:");
        for (category, count) in &self.rules_by_category {
            println!("  {}: {}", category, count);
        }
        
        println!("\nRules by Severity:");
        for (severity, count) in &self.rules_by_severity {
            println!("  {}: {}", severity, count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = RuleRegistry::new();
        assert_eq!(registry.get_all_rules().len(), 0);
    }

    #[test]
    fn test_register_and_retrieve_rule() {
        // This test would require a mock rule implementation
        // For now, we test the basic structure
        let mut registry = RuleRegistry::new();
        let stats = registry.get_statistics();
        assert_eq!(stats.total_rules, 0);
    }

    #[test]
    fn test_statistics() {
        let registry = RuleRegistry::new();
        let stats = registry.get_statistics();
        assert_eq!(stats.enabled_rules, 0);
        assert_eq!(stats.disabled_rules, 0);
    }
}
