//! Resource Graph module for building and analyzing cloud infrastructure graphs

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet};
use crate::models::*;

/// Main graph structure representing cloud infrastructure
pub struct ResourceGraph {
    graph: DiGraph<CloudResource, ResourceRelationship>,
    node_map: HashMap<ResourceId, NodeIndex>,
    reverse_node_map: HashMap<NodeIndex, ResourceId>,
}

impl ResourceGraph {
    /// Create a new empty resource graph
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            reverse_node_map: HashMap::new(),
        }
    }

    /// Add a resource to the graph
    pub fn add_resource(&mut self, resource: CloudResource) -> Result<(), String> {
        if self.node_map.contains_key(&resource.id) {
            return Err(format!("Resource {} already exists", resource.id));
        }

        let node_idx = self.graph.add_node(resource.clone());
        self.node_map.insert(resource.id.clone(), node_idx);
        self.reverse_node_map.insert(node_idx, resource.id);
        
        Ok(())
    }

    /// Add a relationship between resources
    pub fn add_relationship(
        &mut self,
        source_id: &ResourceId,
        target_id: &ResourceId,
        relationship: ResourceRelationship,
    ) -> Result<(), String> {
        let source_idx = self.node_map.get(source_id)
            .ok_or_else(|| format!("Source resource {} not found", source_id))?;
        let target_idx = self.node_map.get(target_id)
            .ok_or_else(|| format!("Target resource {} not found", target_id))?;

        self.graph.add_edge(*source_idx, *target_idx, relationship);
        Ok(())
    }

    /// Get a resource by ID
    pub fn get_resource(&self, id: &ResourceId) -> Option<&CloudResource> {
        self.node_map.get(id).and_then(|idx| self.graph.node_weight(*idx))
    }

    /// Get all resources of a specific type
    pub fn get_resources_by_type(&self, resource_type: &ResourceType) -> Vec<&CloudResource> {
        self.graph
            .node_indices()
            .filter_map(|idx| {
                self.graph.node_weight(idx).filter(|r| &r.resource_type == resource_type)
            })
            .collect()
    }

    /// Get all resources connected to a given resource
    pub fn get_connected_resources(&self, resource_id: &ResourceId) -> Vec<(&CloudResource, &ResourceRelationship)> {
        let node_idx = match self.node_map.get(resource_id) {
            Some(idx) => idx,
            None => return Vec::new(),
        };

        self.graph
            .edges(*node_idx)
            .map(|edge| {
                let target_idx = edge.target();
                let target_resource = self.graph.node_weight(target_idx).unwrap();
                let relationship = edge.weight();
                (target_resource, relationship)
            })
            .collect()
    }

    /// Find all paths between two resources
    pub fn find_paths(&self, start_id: &ResourceId, end_id: &ResourceId) -> Vec<Vec<&CloudResource>> {
        let start_idx = match self.node_map.get(start_id) {
            Some(idx) => *idx,
            None => return Vec::new(),
        };
        let end_idx = match self.node_map.get(end_id) {
            Some(idx) => *idx,
            None => return Vec::new(),
        };

        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = Vec::new();
        
        self.dfs_paths(start_idx, end_idx, &mut visited, &mut current_path, &mut paths);
        
        paths
    }

    fn dfs_paths(
        &self,
        current: NodeIndex,
        end: NodeIndex,
        visited: &mut HashSet<NodeIndex>,
        path: &mut Vec<&CloudResource>,
        all_paths: &mut Vec<Vec<&CloudResource>>,
    ) {
        visited.insert(current);
        
        if let Some(resource) = self.graph.node_weight(current) {
            path.push(resource);
        }

        if current == end {
            all_paths.push(path.clone());
        } else {
            for neighbor in self.graph.neighbors(current) {
                if !visited.contains(&neighbor) {
                    self.dfs_paths(neighbor, end, visited, path, all_paths);
                }
            }
        }

        visited.remove(&current);
        path.pop();
    }

    /// Find resources that are publicly exposed
    pub fn get_public_resources(&self) -> Vec<&CloudResource> {
        self.graph
            .node_indices()
            .filter_map(|idx| {
                self.graph.node_weight(idx).filter(|r| r.is_public)
            })
            .collect()
    }

    /// Find resources with encryption disabled
    pub fn get_unencrypted_resources(&self) -> Vec<&CloudResource> {
        self.graph
            .node_indices()
            .filter_map(|idx| {
                self.graph.node_weight(idx).filter(|r| {
                    r.encryption_status == EncryptionStatus::Disabled
                })
            })
            .collect()
    }

    /// Get graph statistics
    pub fn get_statistics(&self) -> GraphStatistics {
        let node_count = self.graph.node_count();
        let edge_count = self.graph.edge_count();
        
        let mut resource_types = HashMap::new();
        let mut providers = HashMap::new();
        
        for node_idx in self.graph.node_indices() {
            if let Some(resource) = self.graph.node_weight(node_idx) {
                *resource_types.entry(resource.resource_type.clone()).or_insert(0) += 1;
                *providers.entry(resource.provider.clone()).or_insert(0) += 1;
            }
        }

        GraphStatistics {
            total_resources: node_count,
            total_relationships: edge_count,
            resource_types,
            providers,
            public_resources: self.get_public_resources().len(),
            unencrypted_resources: self.get_unencrypted_resources().len(),
        }
    }

    /// Export graph to JSON-serializable format
    pub fn to_export_format(&self) -> GraphExport {
        let nodes: Vec<ExportNode> = self.graph
            .node_indices()
            .filter_map(|idx| {
                self.graph.node_weight(idx).map(|resource| {
                    ExportNode {
                        id: resource.id.clone(),
                        name: resource.name.clone(),
                        resource_type: format!("{}", resource.resource_type),
                        provider: format!("{}", resource.provider),
                        is_public: resource.is_public,
                    }
                })
            })
            .collect();

        let edges: Vec<ExportEdge> = self.graph
            .edge_indices()
            .filter_map(|idx| {
                self.graph.edge_weight(idx).map(|rel| {
                    ExportEdge {
                        source: rel.source_id.clone(),
                        target: rel.target_id.clone(),
                        relationship_type: format!("{}", rel.relationship_type),
                    }
                })
            })
            .collect();

        GraphExport { nodes, edges }
    }
}

impl Default for ResourceGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the resource graph
#[derive(Debug, Clone)]
pub struct GraphStatistics {
    pub total_resources: usize,
    pub total_relationships: usize,
    pub resource_types: HashMap<ResourceType, usize>,
    pub providers: HashMap<CloudProvider, usize>,
    pub public_resources: usize,
    pub unencrypted_resources: usize,
}

/// Export format for graph visualization
#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphExport {
    pub nodes: Vec<ExportNode>,
    pub edges: Vec<ExportEdge>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportNode {
    pub id: String,
    pub name: String,
    pub resource_type: String,
    pub provider: String,
    pub is_public: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportEdge {
    pub source: String,
    pub target: String,
    pub relationship_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_resource(id: &str, name: &str, resource_type: ResourceType) -> CloudResource {
        CloudResource {
            id: id.to_string(),
            arn: format!("arn:test:{}", id),
            name: name.to_string(),
            resource_type,
            provider: CloudProvider::AWS,
            region: Some("us-east-1".to_string()),
            metadata: HashMap::new(),
            tags: HashMap::new(),
            created_at: None,
            updated_at: None,
            is_public: false,
            encryption_status: EncryptionStatus::Enabled,
        }
    }

    #[test]
    fn test_add_resource() {
        let mut graph = ResourceGraph::new();
        let resource = create_test_resource("vm-1", "Test VM", ResourceType::VM);
        
        assert!(graph.add_resource(resource).is_ok());
        assert_eq!(graph.get_statistics().total_resources, 1);
    }

    #[test]
    fn test_add_relationship() {
        let mut graph = ResourceGraph::new();
        
        let vm = create_test_resource("vm-1", "Test VM", ResourceType::VM);
        let sg = create_test_resource("sg-1", "Security Group", ResourceType::SecurityGroup);
        
        graph.add_resource(vm).unwrap();
        graph.add_resource(sg).unwrap();
        
        let relationship = ResourceRelationship {
            source_id: "vm-1".to_string(),
            target_id: "sg-1".to_string(),
            relationship_type: RelationshipType::Protects,
            description: "Security group protects VM".to_string(),
            metadata: HashMap::new(),
        };
        
        assert!(graph.add_relationship(&"vm-1".to_string(), &"sg-1".to_string(), relationship).is_ok());
        assert_eq!(graph.get_statistics().total_relationships, 1);
    }

    #[test]
    fn test_get_public_resources() {
        let mut graph = ResourceGraph::new();
        
        let mut public_resource = create_test_resource("bucket-1", "Public Bucket", ResourceType::Bucket);
        public_resource.is_public = true;
        
        let private_resource = create_test_resource("db-1", "Private DB", ResourceType::Database);
        
        graph.add_resource(public_resource).unwrap();
        graph.add_resource(private_resource).unwrap();
        
        let public_resources = graph.get_public_resources();
        assert_eq!(public_resources.len(), 1);
        assert_eq!(public_resources[0].name, "Public Bucket");
    }
}
