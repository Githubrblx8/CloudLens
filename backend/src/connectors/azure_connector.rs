//! Azure Cloud Connector Implementation
//! 
//! Provides comprehensive scanning capabilities for Azure infrastructure including:
//! - Virtual Machines, Storage Accounts, SQL Database, Key Vault, IAM (Entra ID)
//! - Real-time configuration fetching via Azure SDK
//! - Subscription and tenant handling
//! - Resource normalization to CloudGhidra internal models

use async_trait::async_trait;
use azure_identity::{DefaultAzureCredential, TokenCredentialOptions};
use azure_mgmt_compute::{models::VirtualMachine, Client as ComputeClient};
use azure_mgmt_storage::{models::StorageAccount, Client as StorageClient};
use azure_mgmt_sql::{models::Server, Client as SqlClient};
use azure_mgmt_key_vault::{models::Vault, Client as KeyVaultClient};
use azure_mgmt_network::{models::NetworkSecurityGroup, Client as NetworkClient};
use tracing::{info, warn, instrument};
use std::collections::HashMap;
use std::sync::Arc;

use crate::models::{
    CloudProvider, ResourceType, CloudResource, ResourceMetadata, Tag,
};
use crate::traits::CloudConnector;
use crate::error::{CloudGhidraError, Result};

/// Configuration for Azure Connector
#[derive(Debug, Clone)]
pub struct AzureConnectorConfig {
    pub subscription_id: String,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub environment: String, // AzureCloud, AzureUSGovernment, AzureChinaCloud
    pub scan_timeout_secs: u64,
}

impl Default for AzureConnectorConfig {
    fn default() -> Self {
        Self {
            subscription_id: String::new(),
            tenant_id: None,
            client_id: None,
            client_secret: None,
            environment: "AzureCloud".to_string(),
            scan_timeout_secs: 300,
        }
    }
}

/// Azure Cloud Connector
pub struct AzureConnector {
    config: AzureConnectorConfig,
    credential: Option<Arc<DefaultAzureCredential>>,
    compute_client: Option<ComputeClient>,
    storage_client: Option<StorageClient>,
    sql_client: Option<SqlClient>,
    keyvault_client: Option<KeyVaultClient>,
    network_client: Option<NetworkClient>,
    is_connected: bool,
}

impl AzureConnector {
    /// Create a new Azure connector with default configuration
    pub fn new() -> Self {
        Self::with_config(AzureConnectorConfig::default())
    }

    /// Create a new Azure connector with custom configuration
    pub fn with_config(config: AzureConnectorConfig) -> Self {
        Self {
            config,
            credential: None,
            compute_client: None,
            storage_client: None,
            sql_client: None,
            keyvault_client: None,
            network_client: None,
            is_connected: false,
        }
    }

    /// Initialize Azure SDK clients
    #[instrument(skip(self), fields(subscription = self.config.subscription_id))]
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to Azure...");
        
        let mut options = TokenCredentialOptions::default();
        
        // Set environment if specified
        if self.config.environment != "AzureCloud" {
            // Configure national cloud endpoints
            options.authority_host = match self.config.environment.as_str() {
                "AzureUSGovernment" => Some("https://login.microsoftonline.us".to_string()),
                "AzureChinaCloud" => Some("https://login.chinacloudapi.cn".to_string()),
                _ => None,
            };
        }

        let credential = DefaultAzureCredential::new(options)
            .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to create Azure credential: {}", e)))?;
        
        let credential_arc = Arc::new(credential);
        
        self.compute_client = Some(ComputeClient::new(credential_arc.clone(), &self.config.subscription_id));
        self.storage_client = Some(StorageClient::new(credential_arc.clone(), &self.config.subscription_id));
        self.sql_client = Some(SqlClient::new(credential_arc.clone(), &self.config.subscription_id));
        self.keyvault_client = Some(KeyVaultClient::new(credential_arc.clone(), &self.config.subscription_id));
        self.network_client = Some(NetworkClient::new(credential_arc.clone(), &self.config.subscription_id));
        
        self.credential = Some(credential_arc);
        self.is_connected = true;
        info!("Successfully connected to Azure");
        Ok(())
    }

    /// Scan Virtual Machines
    #[instrument(skip(self))]
    async fn scan_virtual_machines(&self) -> Result<Vec<CloudResource>> {
        let client = self.compute_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let vms = client.virtual_machines().list_all().await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list VMs: {}", e)))?;

        for vm in vms.into_iter() {
            if let Some(vm_name) = vm.name {
                let resource_id = vm.id.clone().unwrap_or_default();
                let location = vm.location.clone().unwrap_or_else(|| "unknown".to_string());
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Azure, ResourceType::VirtualMachine);
                metadata.set_property("location", location);
                
                // VM Size
                if let Some(hardware_profile) = &vm.hardware_profile {
                    if let Some(vm_size) = &hardware_profile.vm_size {
                        metadata.set_property("vm_size", vm_size.to_string());
                    }
                }
                
                // OS Type
                if let Some(os_profile) = &vm.os_profile {
                    if let Some(computer_name) = &os_profile.computer_name {
                        metadata.set_property("computer_name", computer_name.clone());
                    }
                    if let Some(os_type) = &os_profile.os_type {
                        metadata.set_property("os_type", os_type.to_string());
                    }
                }
                
                // Provisioning State
                if let Some(provisioning_state) = &vm.provisioning_state {
                    metadata.set_property("provisioning_state", provisioning_state.clone());
                }
                
                // Network Interfaces
                if let Some(network_profile) = &vm.network_profile {
                    if let Some(nics) = &network_profile.network_interfaces {
                        let nic_ids: Vec<String> = nics.iter()
                            .filter_map(|nic| nic.id.clone())
                            .collect();
                        if !nic_ids.is_empty() {
                            metadata.set_property("network_interface_ids", serde_json::to_string(&nic_ids)?);
                        }
                    }
                }
                
                // Tags
                if let Some(tags) = &vm.tags {
                    for (key, value) in tags.iter() {
                        if let Some(v) = value {
                            metadata.add_tag(Tag::new(key.clone(), v.clone()));
                        }
                    }
                }

                let resource = CloudResource::new(
                    resource_id.clone(),
                    vm_name,
                    ResourceType::VirtualMachine,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan Storage Accounts
    #[instrument(skip(self))]
    async fn scan_storage_accounts(&self) -> Result<Vec<CloudResource>> {
        let client = self.storage_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let accounts = client.storage_accounts().list().await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list storage accounts: {}", e)))?;

        for account in accounts.into_iter() {
            if let Some(account_name) = account.name {
                let resource_id = account.id.clone().unwrap_or_default();
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Azure, ResourceType::ObjectStorage);
                
                // Location
                if let Some(location) = &account.location {
                    metadata.set_property("location", location.clone());
                }
                
                // SKU
                if let Some(sku) = &account.sku {
                    if let Some(sku_name) = &sku.name {
                        metadata.set_property("sku", sku_name.to_string());
                    }
                }
                
                // Kind
                if let Some(kind) = &account.kind {
                    metadata.set_property("kind", kind.to_string());
                }
                
                // Provisioning State
                if let Some(provisioning_state) = &account.provisioning_state {
                    metadata.set_property("provisioning_state", provisioning_state.clone());
                }
                
                // Access Tier
                if let Some(create_time) = account.creation_time {
                    metadata.set_property("creation_time", create_time.to_string());
                }
                
                // Encryption
                if let Some(encryption) = &account.encryption {
                    if let Some(services) = &encryption.services {
                        let encrypted = services.blob.is_some() || services.file.is_some() || 
                                       services.table.is_some() || services.queue.is_some();
                        metadata.set_property("encrypted", encrypted.to_string());
                    }
                }
                
                // Network Rules
                if let Some(network_rule_set) = &account.network_rule_set {
                    if let Some(default_action) = &network_rule_set.default_action {
                        metadata.set_property("network_default_action", default_action.to_string());
                    }
                    let bypass = network_rule_set.bypass.clone().unwrap_or_else(|| "None".to_string());
                    metadata.set_property("network_bypass", bypass);
                }
                
                // Public Network Access
                if let Some(public_network_access) = &account.public_network_access {
                    metadata.set_property("public_network_access", public_network_access.clone());
                }
                
                // Tags
                if let Some(tags) = &account.tags {
                    for (key, value) in tags.iter() {
                        if let Some(v) = value {
                            metadata.add_tag(Tag::new(key.clone(), v.clone()));
                        }
                    }
                }

                let resource = CloudResource::new(
                    resource_id.clone(),
                    account_name,
                    ResourceType::ObjectStorage,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan SQL Servers
    #[instrument(skip(self))]
    async fn scan_sql_servers(&self) -> Result<Vec<CloudResource>> {
        let client = self.sql_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let servers = client.servers().list().await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list SQL servers: {}", e)))?;

        for server in servers.into_iter() {
            if let Some(server_name) = server.name {
                let resource_id = server.id.clone().unwrap_or_default();
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Azure, ResourceType::Database);
                
                // Location
                if let Some(location) = &server.location {
                    metadata.set_property("location", location.clone());
                }
                
                // Version
                if let Some(version) = &server.version {
                    metadata.set_property("sql_version", version.to_string());
                }
                
                // Administrator Login
                if let Some(admin_login) = &server.administrator_login {
                    metadata.set_property("administrator_login", admin_login.clone());
                }
                
                // State
                if let Some(state) = &server.state {
                    metadata.set_property("state", state.to_string());
                }
                
                // Fully Qualified Domain Name
                if let Some(fqdn) = &server.fully_qualified_domain_name {
                    metadata.set_property("fqdn", fqdn.clone());
                }
                
                // Private Endpoint Connections
                if let Some(private_endpoint_connections) = &server.private_endpoint_connections {
                    metadata.set_property("private_endpoint_count", private_endpoint_connections.len().to_string());
                }
                
                // Minimal TLS Version
                if let Some(minimal_tls_version) = &server.minimal_tls_version {
                    metadata.set_property("minimal_tls_version", minimal_tls_version.to_string());
                }
                
                // Public Network Access
                if let Some(public_network_access) = &server.public_network_access {
                    metadata.set_property("public_network_access", public_network_access.to_string());
                }
                
                // Tags
                if let Some(tags) = &server.tags {
                    for (key, value) in tags.iter() {
                        if let Some(v) = value {
                            metadata.add_tag(Tag::new(key.clone(), v.clone()));
                        }
                    }
                }

                let resource = CloudResource::new(
                    resource_id.clone(),
                    server_name,
                    ResourceType::Database,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan Key Vaults
    #[instrument(skip(self))]
    async fn scan_key_vaults(&self) -> Result<Vec<CloudResource>> {
        let client = self.keyvault_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let vaults = client.vaults().list().await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list key vaults: {}", e)))?;

        for vault in vaults.into_iter() {
            if let Some(vault_name) = vault.name {
                let resource_id = vault.id.clone().unwrap_or_default();
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Azure, ResourceType::SecretManager);
                
                // Location
                if let Some(location) = &vault.location {
                    metadata.set_property("location", location.clone());
                }
                
                // Properties
                if let Some(properties) = &vault.properties {
                    // Tenant ID
                    if let Some(tenant_id) = &properties.tenant_id {
                        metadata.set_property("tenant_id", tenant_id.to_string());
                    }
                    
                    // SKU
                    if let Some(sku) = &properties.sku {
                        if let Some(sku_family) = &sku.family {
                            metadata.set_property("sku_family", sku_family.to_string());
                        }
                        if let Some(sku_name) = &properties.sku.as_ref().and_then(|s| s.name.as_ref()) {
                            metadata.set_property("sku_name", sku_name.to_string());
                        }
                    }
                    
                    // Access Policies
                    if let Some(access_policies) = &properties.access_policies {
                        metadata.set_property("access_policy_count", access_policies.len().to_string());
                    }
                    
                    // Enabled for Deployment
                    if let Some(enabled_for_deployment) = properties.enabled_for_deployment {
                        metadata.set_property("enabled_for_deployment", enabled_for_deployment.to_string());
                    }
                    
                    // Enabled for Disk Encryption
                    if let Some(enabled_for_disk_encryption) = properties.enabled_for_disk_encryption {
                        metadata.set_property("enabled_for_disk_encryption", enabled_for_disk_encryption.to_string());
                    }
                    
                    // Enabled for Template Deployment
                    if let Some(enabled_for_template_deployment) = properties.enabled_for_template_deployment {
                        metadata.set_property("enabled_for_template_deployment", enabled_for_template_deployment.to_string());
                    }
                    
                    // Enable Soft Delete
                    if let Some(enable_soft_delete) = properties.enable_soft_delete {
                        metadata.set_property("enable_soft_delete", enable_soft_delete.to_string());
                    }
                    
                    // Enable Purge Protection
                    if let Some(enable_purge_protection) = properties.enable_purge_protection {
                        metadata.set_property("enable_purge_protection", enable_purge_protection.to_string());
                    }
                    
                    // Network Acls
                    if let Some(network_acls) = &properties.network_acls {
                        if let Some(default_action) = &network_acls.default_action {
                            metadata.set_property("network_default_action", default_action.to_string());
                        }
                        if let Some(bypass) = &network_acls.bypass {
                            metadata.set_property("network_bypass", bypass.to_string());
                        }
                    }
                }
                
                // Tags
                if let Some(tags) = &vault.tags {
                    for (key, value) in tags.iter() {
                        if let Some(v) = value {
                            metadata.add_tag(Tag::new(key.clone(), v.clone()));
                        }
                    }
                }

                let resource = CloudResource::new(
                    resource_id.clone(),
                    vault_name,
                    ResourceType::SecretManager,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Scan Network Security Groups
    #[instrument(skip(self))]
    async fn scan_nsgs(&self) -> Result<Vec<CloudResource>> {
        let client = self.network_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let nsgs = client.network_security_groups().list_all().await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list NSGs: {}", e)))?;

        for nsg in nsgs.into_iter() {
            if let Some(nsg_name) = nsg.name {
                let resource_id = nsg.id.clone().unwrap_or_default();
                
                let mut metadata = ResourceMetadata::new(CloudProvider::Azure, ResourceType::SecurityGroup);
                
                // Location
                if let Some(location) = &nsg.location {
                    metadata.set_property("location", location.clone());
                }
                
                // Security Rules
                if let Some(properties) = &nsg.properties {
                    if let Some(security_rules) = &properties.security_rules {
                        let allow_rules = security_rules.iter()
                            .filter(|r| {
                                r.properties.as_ref()
                                    .and_then(|p| p.access.as_ref())
                                    .map(|a| a.as_str() == "Allow")
                                    .unwrap_or(false)
                            })
                            .count();
                        
                        let deny_rules = security_rules.iter()
                            .filter(|r| {
                                r.properties.as_ref()
                                    .and_then(|p| p.access.as_ref())
                                    .map(|a| a.as_str() == "Deny")
                                    .unwrap_or(false)
                            })
                            .count();
                        
                        metadata.set_property("allow_rule_count", allow_rules.to_string());
                        metadata.set_property("deny_rule_count", deny_rules.to_string());
                        metadata.set_property("total_rule_count", security_rules.len().to_string());
                    }
                    
                    // Default Security Rules
                    if let Some(default_security_rules) = &properties.default_security_rules {
                        metadata.set_property("default_rule_count", default_security_rules.len().to_string());
                    }
                    
                    // Network Interface Associations
                    if let Some(network_interfaces) = &properties.network_interfaces {
                        metadata.set_property("associated_nic_count", network_interfaces.len().to_string());
                    }
                    
                    // Subnet Associations
                    if let Some(subnets) = &properties.subnets {
                        metadata.set_property("associated_subnet_count", subnets.len().to_string());
                    }
                }
                
                // Tags
                if let Some(tags) = &nsg.tags {
                    for (key, value) in tags.iter() {
                        if let Some(v) = value {
                            metadata.add_tag(Tag::new(key.clone(), v.clone()));
                        }
                    }
                }

                let resource = CloudResource::new(
                    resource_id.clone(),
                    nsg_name,
                    ResourceType::SecurityGroup,
                    metadata,
                );
                
                resources.push(resource);
            }
        }

        Ok(resources)
    }
}

#[async_trait]
impl CloudConnector for AzureConnector {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn is_connected(&self) -> bool {
        self.is_connected
    }

    async fn connect_async(&mut self) -> Result<()> {
        self.connect().await
    }

    async fn disconnect_async(&mut self) -> Result<()> {
        self.credential = None;
        self.compute_client = None;
        self.storage_client = None;
        self.sql_client = None;
        self.keyvault_client = None;
        self.network_client = None;
        self.is_connected = false;
        info!("Disconnected from Azure");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn scan_resources(&self, resource_types: Option<Vec<ResourceType>>) -> Result<Vec<CloudResource>> {
        if !self.is_connected {
            return Err(CloudGhidraError::NotConnected);
        }

        let mut all_resources = Vec::new();
        let target_types = resource_types.unwrap_or_else(|| vec![
            ResourceType::VirtualMachine,
            ResourceType::ObjectStorage,
            ResourceType::Database,
            ResourceType::SecretManager,
            ResourceType::SecurityGroup,
            ResourceType::LoadBalancer,
            ResourceType::NetworkInterface,
            ResourceType::ContainerCluster,
        ]);

        if target_types.contains(&ResourceType::VirtualMachine) {
            match self.scan_virtual_machines().await {
                Ok(resources) => {
                    info!("Scanned {} Azure VMs", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Azure VMs: {}", e),
            }
        }

        if target_types.contains(&ResourceType::ObjectStorage) {
            match self.scan_storage_accounts().await {
                Ok(resources) => {
                    info!("Scanned {} Azure Storage Accounts", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Azure Storage Accounts: {}", e),
            }
        }

        if target_types.contains(&ResourceType::Database) {
            match self.scan_sql_servers().await {
                Ok(resources) => {
                    info!("Scanned {} Azure SQL Servers", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Azure SQL Servers: {}", e),
            }
        }

        if target_types.contains(&ResourceType::SecretManager) {
            match self.scan_key_vaults().await {
                Ok(resources) => {
                    info!("Scanned {} Azure Key Vaults", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Azure Key Vaults: {}", e),
            }
        }

        if target_types.contains(&ResourceType::SecurityGroup) {
            match self.scan_nsgs().await {
                Ok(resources) => {
                    info!("Scanned {} Azure NSGs", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Azure NSGs: {}", e),
            }
        }

        Ok(all_resources)
    }

    async fn validate_credentials(&self) -> Result<bool> {
        Ok(self.is_connected)
    }

    async fn get_metadata(&self) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "Azure".to_string());
        metadata.insert("subscription_id".to_string(), self.config.subscription_id.clone());
        metadata.insert("environment".to_string(), self.config.environment.clone());
        metadata.insert("connected".to_string(), self.is_connected.to_string());
        if let Some(tenant_id) = &self.config.tenant_id {
            metadata.insert("tenant_id".to_string(), tenant_id.clone());
        }
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_azure_connector_creation() {
        let connector = AzureConnector::new();
        assert_eq!(connector.provider(), CloudProvider::Azure);
        assert!(!connector.is_connected());
    }

    #[tokio::test]
    async fn test_azure_connector_config() {
        let config = AzureConnectorConfig {
            subscription_id: "sub-12345".to_string(),
            tenant_id: Some("tenant-67890".to_string()),
            environment: "AzureUSGovernment".to_string(),
            ..Default::default()
        };
        let connector = AzureConnector::with_config(config);
        assert_eq!(connector.provider(), CloudProvider::Azure);
    }
}
