//! CloudLens Core Library
//! 
//! This library provides the core functionality for analyzing cloud infrastructures,
//! building resource graphs, and detecting security risks.

pub mod graph;
pub mod models;
pub mod analyzer;
pub mod risk_detector;
pub mod iam_analyzer;
pub mod connectors;

pub use graph::ResourceGraph;
pub use models::*;
pub use analyzer::InfrastructureAnalyzer;
pub use risk_detector::RiskDetector;
pub use iam_analyzer::IAMAnalyzer;
