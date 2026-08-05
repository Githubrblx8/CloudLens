//! CloudGhidra Server - Main entry point
//! 
//! This is the main server binary for CloudGhidra, providing REST APIs
//! for cloud infrastructure analysis and security risk detection.

use axum::{
    routing::{get, post},
    Json, Router,
    extract::State,
    http::StatusCode,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use cloudghidra_core::{
    InfrastructureAnalyzer,
    CloudResource,
    ResourceType,
    CloudProvider,
    EncryptionStatus,
};

/// Application state shared across handlers
#[derive(Clone)]
struct AppState {
    analyzer: Arc<RwLock<InfrastructureAnalyzer>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            analyzer: Arc::new(RwLock::new(InfrastructureAnalyzer::new())),
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloudghidra=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting CloudGhidra Server...");

    // Create application state
    let state = AppState::new();

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/analyze", get(run_analysis))
        .route("/api/v1/resources", get(list_resources))
        .route("/api/v1/resources", post(add_resource))
        .route("/api/v1/risks", get(list_risks))
        .route("/api/v1/graph", get(get_graph))
        .route("/api/v1/recommendations", get(get_recommendations))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr = "0.0.0.0:3000";
    tracing::info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Run complete infrastructure analysis
async fn run_analysis(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let analyzer = state.analyzer.read().await;
    
    match serde_json::to_value(analyzer.analyze()) {
        Ok(value) => Ok(Json(value)),
        Err(e) => {
            tracing::error!("Failed to serialize analysis results: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List all resources in the graph
async fn list_resources(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let graph = analyzer.graph();
    let stats = graph.get_statistics();
    
    let response = serde_json::json!({
        "total_resources": stats.total_resources,
        "total_relationships": stats.total_relationships,
        "public_resources": stats.public_resources,
        "unencrypted_resources": stats.unencrypted_resources,
        "resource_types": stats.resource_types.iter().map(|(k, v)| {
            (format!("{}", k), v)
        }).collect::<std::collections::HashMap<_, _>>(),
    });
    
    Ok(Json(response))
}

/// Add a new resource to the graph
async fn add_resource(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut analyzer = state.analyzer.write().await;
    
    // Parse resource from JSON payload
    let resource: CloudResource = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to parse resource: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    
    match analyzer.add_resource(resource.clone()) {
        Ok(_) => {
            tracing::info!("Added resource: {}", resource.id);
            Ok(Json(serde_json::json!({
                "status": "success",
                "resource_id": resource.id,
            })))
        }
        Err(e) => {
            tracing::warn!("Failed to add resource: {}", e);
            Err(StatusCode::CONFLICT)
        }
    }
}

/// List detected security risks
async fn list_risks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let report = analyzer.analyze();
    
    let response = serde_json::json!({
        "total_risks": report.summary.total_risks,
        "critical": report.summary.critical_risks,
        "high": report.summary.high_risks,
        "medium": report.summary.medium_risks,
        "low": report.summary.low_risks,
        "risk_score": report.summary.risk_score,
        "risks": report.risks.iter().map(|r| {
            serde_json::json!({
                "id": r.id,
                "title": r.title,
                "severity": format!("{}", r.severity),
                "category": format!("{}", r.category),
                "affected_resources": r.affected_resources.len(),
            })
        }).collect::<Vec<_>>(),
    });
    
    Ok(Json(response))
}

/// Get the infrastructure graph
async fn get_graph(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let graph_export = analyzer.graph().to_export_format();
    
    match serde_json::to_value(graph_export) {
        Ok(value) => Ok(Json(value)),
        Err(e) => {
            tracing::error!("Failed to serialize graph: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get security recommendations
async fn get_recommendations(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let report = analyzer.analyze();
    
    let response = serde_json::json!({
        "recommendations": report.recommendations.iter().map(|r| {
            serde_json::json!({
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "priority": format!("{:?}", r.priority),
                "affected_resources_count": r.affected_resources.len(),
            })
        }).collect::<Vec<_>>(),
    });
    
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check() {
        let state = AppState::new();
        let app = Router::new()
            .route("/health", get(health_check))
            .with_state(state);

        let response = app
            .oneshot(axum::Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_add_and_list_resources() {
        let state = AppState::new();
        
        // Add a test resource
        let mut analyzer = state.analyzer.write().await;
        let test_resource = CloudResource {
            id: "test-vm-1".to_string(),
            arn: "arn:aws:ec2:us-east-1:123456789012:instance/i-test".to_string(),
            name: "TestVM".to_string(),
            resource_type: ResourceType::VM,
            provider: CloudProvider::AWS,
            region: Some("us-east-1".to_string()),
            metadata: std::collections::HashMap::new(),
            tags: std::collections::HashMap::new(),
            created_at: None,
            updated_at: None,
            is_public: false,
            encryption_status: EncryptionStatus::Enabled,
        };
        analyzer.add_resource(test_resource).unwrap();
        drop(analyzer);
        
        // List resources
        let resources_response = list_resources(State(state.clone())).await.unwrap();
        assert_eq!(resources_response.0["total_resources"], 1);
        
        // Run analysis
        let analysis_response = run_analysis(State(state.clone())).await.unwrap();
        assert!(analysis_response.0["summary"]["total_resources"].as_u64().unwrap() >= 1);
    }
}
