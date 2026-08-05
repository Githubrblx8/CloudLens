//! Infrastructure Analyzer - Main analysis engine for cloud infrastructure

use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;
use crate::models::*;
use crate::graph::ResourceGraph;
use crate::risk_detector::RiskDetector;
use crate::iam_analyzer::IAMAnalyzer;

/// Main infrastructure analyzer that orchestrates all analysis components
pub struct InfrastructureAnalyzer {
    graph: ResourceGraph,
    risk_detector: RiskDetector,
    iam_analyzer: IAMAnalyzer,
}

impl InfrastructureAnalyzer {
    /// Create a new infrastructure analyzer
    pub fn new() -> Self {
        Self {
            graph: ResourceGraph::new(),
            risk_detector: RiskDetector::new(),
            iam_analyzer: IAMAnalyzer::new(),
        }
    }

    /// Get a reference to the resource graph
    pub fn graph(&self) -> &ResourceGraph {
        &self.graph
    }

    /// Get a mutable reference to the resource graph
    pub fn graph_mut(&mut self) -> &mut ResourceGraph {
        &mut self.graph
    }

    /// Add a resource to the infrastructure graph
    pub fn add_resource(&mut self, resource: CloudResource) -> Result<(), String> {
        self.graph.add_resource(resource)
    }

    /// Add a relationship between resources
    pub fn add_relationship(
        &mut self,
        source_id: &ResourceId,
        target_id: &ResourceId,
        relationship: ResourceRelationship,
    ) -> Result<(), String> {
        self.graph.add_relationship(source_id, target_id, relationship)
    }

    /// Run a complete infrastructure analysis
    pub fn analyze(&self) -> AnalysisReport {
        let started_at = Utc::now();
        
        // Detect security risks
        let risks = self.risk_detector.analyze(&self.graph);
        
        // Analyze IAM configurations
        let mut iam_analyzer = IAMAnalyzer::new();
        let iam_result = iam_analyzer.analyze_policies(&self.graph);
        
        // Get graph statistics
        let stats = self.graph.get_statistics();
        
        // Calculate overall risk score
        let risk_score = self.calculate_risk_score(&risks);
        
        let completed_at = Utc::now();
        
        AnalysisReport {
            report_id: Uuid::new_v4(),
            generated_at: started_at,
            completed_at,
            summary: AnalysisSummary {
                total_resources: stats.total_resources,
                total_relationships: stats.total_relationships,
                public_resources: stats.public_resources,
                unencrypted_resources: stats.unencrypted_resources,
                total_risks: risks.len(),
                critical_risks: risks.iter().filter(|r| r.severity == RiskSeverity::Critical).count(),
                high_risks: risks.iter().filter(|r| r.severity == RiskSeverity::High).count(),
                medium_risks: risks.iter().filter(|r| r.severity == RiskSeverity::Medium).count(),
                low_risks: risks.iter().filter(|r| r.severity == RiskSeverity::Low).count(),
                risk_score,
            },
            risks,
            iam_findings: iam_result.findings,
            privilege_escalation_paths: iam_result.escalation_paths,
            overly_permissive_identities: iam_result.overly_permissive,
            graph_export: self.graph.to_export_format(),
            recommendations: self.generate_recommendations(&risks, &iam_result),
        }
    }

    /// Calculate an overall risk score (0-100)
    fn calculate_risk_score(&self, risks: &[SecurityRisk]) -> u32 {
        if risks.is_empty() {
            return 0;
        }

        let mut score = 0u32;
        
        for risk in risks {
            match risk.severity {
                RiskSeverity::Critical => score += 25,
                RiskSeverity::High => score += 15,
                RiskSeverity::Medium => score += 8,
                RiskSeverity::Low => score += 3,
                RiskSeverity::Info => score += 1,
            }
        }

        // Cap at 100
        score.min(100)
    }

    /// Generate actionable recommendations based on analysis results
    fn generate_recommendations(&self, risks: &[SecurityRisk], iam_result: &crate::iam_analyzer::IAMAnalysisResult) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();
        
        // Group risks by category
        let mut risks_by_category: std::collections::HashMap<RiskCategory, Vec<&SecurityRisk>> = 
            std::collections::HashMap::new();
        
        for risk in risks {
            risks_by_category.entry(risk.category.clone())
                .or_insert_with(Vec::new)
                .push(risk);
        }
        
        // Generate recommendations for each category with issues
        for (category, category_risks) in &risks_by_category {
            let priority = match category {
                RiskCategory::ExposedResource => RecommendationPriority::Critical,
                RiskCategory::ExcessivePermissions => RecommendationPriority::High,
                RiskCategory::IdentityRisk => RecommendationPriority::High,
                RiskCategory::MissingEncryption => RecommendationPriority::High,
                RiskCategory::NetworkMisconfiguration => RecommendationPriority::Medium,
                RiskCategory::SecretExposure => RecommendationPriority::High,
                _ => RecommendationPriority::Medium,
            };
            
            let title = match category {
                RiskCategory::ExposedResource => "Restrict Publicly Exposed Resources".to_string(),
                RiskCategory::ExcessivePermissions => "Implement Least Privilege Access".to_string(),
                RiskCategory::IdentityRisk => "Review Identity and Access Management".to_string(),
                RiskCategory::MissingEncryption => "Enable Encryption at Rest".to_string(),
                RiskCategory::NetworkMisconfiguration => "Fix Network Security Configuration".to_string(),
                RiskCategory::SecretExposure => "Secure Secrets and Credentials".to_string(),
                _ => format!("Address {} Issues", category),
            };
            
            let description = format!(
                "Found {} issue(s) related to {}. {}",
                category_risks.len(),
                category,
                category_risks.iter().map(|r| r.recommendation.as_str()).next().unwrap_or("")
            );
            
            recommendations.push(Recommendation {
                id: Uuid::new_v4(),
                title,
                description,
                priority,
                affected_resources: category_risks.iter().flat_map(|r| r.affected_resources.clone()).collect(),
            });
        }
        
        // Add IAM-specific recommendations
        if !iam_result.escalation_paths.is_empty() {
            recommendations.push(Recommendation {
                id: Uuid::new_v4(),
                title: "Eliminate Privilege Escalation Paths".to_string(),
                description: format!(
                    "Detected {} privilege escalation path(s). Review role trust relationships and permissions.",
                    iam_result.escalation_paths.len()
                ),
                priority: RecommendationPriority::Critical,
                affected_resources: iam_result.escalation_paths.iter()
                    .flat_map(|p| vec![p.start_resource.clone(), p.end_resource.clone()])
                    .collect(),
            });
        }
        
        if !iam_result.overly_permissive.is_empty() {
            recommendations.push(Recommendation {
                id: Uuid::new_v4(),
                title: "Reduce Permissions for Overly Permissive Identities".to_string(),
                description: format!(
                    "Found {} identity/identities with excessive permissions. Apply principle of least privilege.",
                    iam_result.overly_permissive.len()
                ),
                priority: RecommendationPriority::High,
                affected_resources: iam_result.overly_permissive.iter()
                    .map(|i| i.identity_id.clone())
                    .collect(),
            });
        }
        
        // Sort by priority
        recommendations.sort_by(|a, b| a.priority.cmp(&b.priority));
        
        recommendations
    }

    /// Export analysis results to JSON
    pub fn export_analysis(&self) -> Result<String, serde_json::Error> {
        let report = self.analyze();
        serde_json::to_string_pretty(&report)
    }
}

impl Default for InfrastructureAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete analysis report
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisReport {
    pub report_id: Uuid,
    pub generated_at: chrono::DateTime<Utc>,
    pub completed_at: chrono::DateTime<Utc>,
    pub summary: AnalysisSummary,
    pub risks: Vec<SecurityRisk>,
    pub iam_findings: Vec<crate::iam_analyzer::IAMFinding>,
    pub privilege_escalation_paths: Vec<AccessPath>,
    pub overly_permissive_identities: Vec<crate::iam_analyzer::OverlyPermissiveIdentity>,
    pub graph_export: crate::graph::GraphExport,
    pub recommendations: Vec<Recommendation>,
}

/// Summary of analysis results
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisSummary {
    pub total_resources: usize,
    pub total_relationships: usize,
    pub public_resources: usize,
    pub unencrypted_resources: usize,
    pub total_risks: usize,
    pub critical_risks: usize,
    pub high_risks: usize,
    pub medium_risks: usize,
    pub low_risks: usize,
    pub risk_score: u32,
}

/// Actionable recommendation
#[derive(Debug, Clone, serde::Serialize)]
pub struct Recommendation {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub priority: RecommendationPriority,
    pub affected_resources: Vec<ResourceId>,
}

/// Recommendation priority levels
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecommendationPriority {
    Critical,
    High,
    Medium,
    Low,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_analyzer() -> InfrastructureAnalyzer {
        let mut analyzer = InfrastructureAnalyzer::new();
        
        // Add a test VM
        let vm = CloudResource {
            id: "vm-1".to_string(),
            arn: "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0".to_string(),
            name: "TestVM".to_string(),
            resource_type: ResourceType::VM,
            provider: CloudProvider::AWS,
            region: Some("us-east-1".to_string()),
            metadata: HashMap::new(),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
            is_public: false,
            encryption_status: EncryptionStatus::Enabled,
        };
        
        analyzer.add_resource(vm).unwrap();
        
        analyzer
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = InfrastructureAnalyzer::new();
        assert_eq!(analyzer.graph().get_statistics().total_resources, 0);
    }

    #[test]
    fn test_add_resource() {
        let mut analyzer = create_test_analyzer();
        assert_eq!(analyzer.graph().get_statistics().total_resources, 1);
    }

    #[test]
    fn test_analyze() {
        let analyzer = create_test_analyzer();
        let report = analyzer.analyze();
        
        assert!(report.report_id != Uuid::nil());
        assert_eq!(report.summary.total_resources, 1);
        assert!(report.risk_score <= 100);
    }

    #[test]
    fn test_risk_score_calculation() {
        let analyzer = InfrastructureAnalyzer::new();
        
        // Empty risks should give score of 0
        assert_eq!(analyzer.calculate_risk_score(&[]), 0);
    }
}
