//! GCP Cloud Connector Implementation
//! 
//! Provides comprehensive scanning capabilities for Google Cloud Platform infrastructure including:
//! - Compute Engine, Cloud Storage, Cloud SQL, IAM, VPC, GKE
//! - Real-time configuration fetching via GCP SDK
//! - Project and organization handling
//! - Resource normalization to CloudGhidra internal models

use async_trait::async_trait;
use gcp_auth::{AuthenticationManager, Client};
use reqwest::Client as HttpClient;
use tracing::{info, warn, instrument};
use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};

use crate::models::{
    CloudProvider, ResourceType, CloudResource, ResourceMetadata, Tag,
};
use crate::traits::CloudConnector;
use crate::error::{CloudGhidraError, Result};

/// Configuration for GCP Connector
#[derive(Debug, Clone)]
pub struct GcpConnectorConfig {
    pub project_id: String,
    pub region: Option<String>,
    pub zones: Vec<String>,
    pub credentials_path: Option<String>,
    pub scan_timeout_secs: u64,
}

impl Default for GcpConnectorConfig {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            region: Some("us-central1".to_string()),
            zones: vec!["us-central1-a".to_string(), "us-central1-b".to_string()],
            credentials_path: None,
            scan_timeout_secs: 300,
        }
    }
}

/// GCP API Response structures
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpInstance {
    id: Option<String>,
    name: Option<String>,
    machineType: Option<String>,
    status: Option<String>,
    zone: Option<String>,
    creationTimestamp: Option<String>,
    networkInterfaces: Option<Vec<GcpNetworkInterface>>,
    tags: Option<GcpTags>,
    labels: Option<HashMap<String, String>>,
    disks: Option<Vec<GcpDisk>>,
    serviceAccounts: Option<Vec<GcpServiceAccount>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpNetworkInterface {
    network: Option<String>,
    subnetwork: Option<String>,
    networkIP: Option<String>,
    accessConfigs: Option<Vec<GcpAccessConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpAccessConfig {
    type_: Option<String>,
    name: Option<String>,
    natIP: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpTags {
    items: Option<Vec<String>>,
    fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpDisk {
    source: Option<String>,
    boot: Option<bool>,
    autoDelete: Option<bool>,
    interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpServiceAccount {
    email: Option<String>,
    scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpBucket {
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    storageClass: Option<String>,
    timeCreated: Option<String>,
    encryption: Option<GcpBucketEncryption>,
    versioning: Option<GcpVersioning>,
    iamConfiguration: Option<GcpIamConfiguration>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpBucketEncryption {
    defaultKmsKeyName: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpVersioning {
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpIamConfiguration {
    bucketPolicyOnly: Option<GcpBucketPolicyOnly>,
    uniformBucketLevelAccess: Option<GcpUniformBucketLevelAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpBucketPolicyOnly {
    enabled: Option<bool>,
    lockedTime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpUniformBucketLevelAccess {
    enabled: Option<bool>,
    lockedTime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpSqlInstance {
    kind: Option<String>,
    name: Option<String>,
    connectionName: Option<String>,
    project: Option<String>,
    backendType: Option<String>,
    region: Option<String>,
    settings: Option<GcpSqlSettings>,
    state: Option<String>,
    ipAddresses: Option<Vec<GcpSqlIpAddress>>,
    instanceType: Option<String>,
    gceZone: Option<String>,
    databaseVersion: Option<String>,
    rootPassword: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpSqlSettings {
    tier: Option<String>,
    availabilityType: Option<String>,
    backupConfiguration: Option<GcpSqlBackupConfiguration>,
    ipConfiguration: Option<GcpSqlIpConfiguration>,
    dataDiskSizeGb: Option<String>,
    dataDiskType: Option<String>,
    storageAutoResize: Option<bool>,
    userLabels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpSqlBackupConfiguration {
    binaryLogEnabled: Option<bool>,
    enabled: Option<bool>,
    startTime: Option<String>,
    location: Option<String>,
    pointInTimeRecoveryEnabled: Option<bool>,
    transactionLogRetentionDays: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpSqlIpConfiguration {
    ipv4Enabled: Option<bool>,
    privateNetwork: Option<String>,
    requireSsl: Option<bool>,
    authorizedNetworks: Option<Vec<GcpSqlAuthorizedNetwork>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpSqlAuthorizedNetwork {
    name: Option<String>,
    value: Option<String>,
    expirationTime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpSqlIpAddress {
    ipAddress: Option<String>,
    type_: Option<String>,
    timeToRetire: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpCluster {
    name: Option<String>,
    description: Option<String>,
    initialNodeCount: Option<i32>,
    locations: Option<Vec<String>>,
    nodeConfig: Option<GcpNodeConfig>,
    loggingService: Option<String>,
    monitoringService: Option<String>,
    network: Option<String>,
    subnetwork: Option<String>,
    clusterIpv4Cidr: Option<String>,
    addonsConfig: Option<GcpAddonsConfig>,
    legacyAbac: Option<GcpLegacyAbac>,
    networkConfig: Option<GcpNetworkConfig>,
    masterAuth: Option<GcpMasterAuth>,
    resourceLabels: Option<HashMap<String, String>>,
    labelFingerprint: Option<String>,
    createTime: Option<String>,
    status: Option<String>,
    endpoint: Option<String>,
    initialClusterVersion: Option<String>,
    currentMasterVersion: Option<String>,
    currentNodeVersion: Option<String>,
    autoscaling: Option<GcpClusterAutoscaling>,
    binaryAuthorization: Option<GcpBinaryAuthorization>,
    releaseChannel: Option<GcpReleaseChannel>,
    workloadIdentityConfig: Option<GcpWorkloadIdentityConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpNodeConfig {
    machineType: Option<String>,
    diskSizeGb: Option<i32>,
    oauthScopes: Option<Vec<String>>,
    serviceAccount: Option<String>,
    metadata: Option<HashMap<String, String>>,
    imageType: Option<String>,
    labels: Option<HashMap<String, String>>,
    localSsdCount: Option<i32>,
    shieldedInstanceConfig: Option<GcpShieldedInstanceConfig>,
    preemptible: Option<bool>,
    acceleratorConfigs: Option<Vec<GcpAcceleratorConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpShieldedInstanceConfig {
    enableSecureBoot: Option<bool>,
    enableVtpm: Option<bool>,
    enableIntegrityMonitoring: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpAcceleratorConfig {
    acceleratorCount: Option<i32>,
    acceleratorType: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpAddonsConfig {
    httpLoadBalancing: Option<GcpHttpLoadBalancing>,
    horizontalPodAutoscaling: Option<GcpHorizontalPodAutoscaling>,
    kubernetesDashboard: Option<GcpKubernetesDashboard>,
    networkPolicyConfig: Option<GcpNetworkPolicyConfig>,
    cloudRunConfig: Option<GcpCloudRunConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpHttpLoadBalancing {
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpHorizontalPodAutoscaling {
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpKubernetesDashboard {
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpNetworkPolicyConfig {
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpCloudRunConfig {
    disabled: Option<bool>,
    loadBalancerType: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpLegacyAbac {
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpNetworkConfig {
    network: Option<String>,
    subnetwork: Option<String>,
    enableIntraNodeVisibility: Option<bool>,
    defaultSnatStatus: Option<GcpDefaultSnatStatus>,
    enableL4ilbSubsetting: Option<bool>,
    datapathProvider: Option<String>,
    privateIpv6GoogleAccess: Option<String>,
    enableIntranodeVisibility: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpDefaultSnatStatus {
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpMasterAuth {
    username: Option<String>,
    password: Option<String>,
    clientCertificateConfig: Option<GcpClientCertificateConfig>,
    clusterCaCertificate: Option<String>,
    clientCertificate: Option<String>,
    clientKey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpClientCertificateConfig {
    issueClientCertificate: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpClusterAutoscaling {
    enableNodeAutoprovisioning: Option<bool>,
    resourceLimits: Option<Vec<GcpResourceLimit>>,
    autoscalingProfile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpResourceLimit {
    resourceType: Option<String>,
    minimum: Option<String>,
    maximum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpBinaryAuthorization {
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpReleaseChannel {
    channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpWorkloadIdentityConfig {
    workloadPool: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpItemListResponse<T> {
    kind: Option<String>,
    id: Option<String>,
    items: Option<Vec<T>>,
    selfLink: Option<String>,
    nextPageToken: Option<String>,
}

/// GCP Cloud Connector
pub struct GcpConnector {
    config: GcpConnectorConfig,
    auth_manager: Option<AuthenticationManager>,
    http_client: Option<HttpClient>,
    is_connected: bool,
}

impl GcpConnector {
    /// Create a new GCP connector with default configuration
    pub fn new() -> Self {
        Self::with_config(GcpConnectorConfig::default())
    }

    /// Create a new GCP connector with custom configuration
    pub fn with_config(config: GcpConnectorConfig) -> Self {
        Self {
            config,
            auth_manager: None,
            http_client: None,
            is_connected: false,
        }
    }

    /// Initialize GCP SDK clients
    #[instrument(skip(self), fields(project = self.config.project_id))]
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to GCP...");
        
        let auth_manager = if let Some(creds_path) = &self.config.credentials_path {
            AuthenticationManager::from_credentials_file(creds_path)
                .await
                .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to load GCP credentials: {}", e)))?
        } else {
            AuthenticationManager::new()
                .await
                .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to initialize GCP auth: {}", e)))?
        };

        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(self.config.scan_timeout_secs))
            .build()
            .map_err(|e| CloudGhidraError::ConfigurationError(format!("Failed to create HTTP client: {}", e)))?;

        self.auth_manager = Some(auth_manager);
        self.http_client = Some(http_client);
        self.is_connected = true;
        info!("Successfully connected to GCP");
        Ok(())
    }

    /// Get authorization header
    async fn get_auth_header(&self) -> Result<String> {
        let auth_manager = self.auth_manager.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let token = auth_manager
            .token("https://www.googleapis.com/auth/cloud-platform")
            .await
            .map_err(|e| CloudGhidraError::AuthenticationError(format!("Failed to get GCP token: {}", e)))?;
        
        Ok(format!("Bearer {}", token.as_str()))
    }

    /// Scan Compute Engine Instances
    #[instrument(skip(self))]
    async fn scan_compute_instances(&self) -> Result<Vec<CloudResource>> {
        let http_client = self.http_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        for zone in &self.config.zones {
            let url = format!(
                "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances",
                self.config.project_id, zone
            );

            let auth_header = self.get_auth_header().await?;
            let response = http_client
                .get(&url)
                .header("Authorization", &auth_header)
                .send()
                .await
                .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list instances: {}", e)))?;

            if !response.status().is_success() {
                warn!("Failed to fetch instances in zone {}: {}", zone, response.status());
                continue;
            }

            let body: GcpItemListResponse<GcpInstance> = response
                .json()
                .await
                .map_err(|e| CloudGhidraError::ParseError(format!("Failed to parse instances response: {}", e)))?;

            if let Some(instances) = body.items {
                for instance in instances {
                    if let Some(instance_name) = &instance.name {
                        let resource_id = instance.id.clone().unwrap_or_default();
                        
                        let mut metadata = ResourceMetadata::new(CloudProvider::Gcp, ResourceType::VirtualMachine);
                        
                        // Zone
                        if let Some(zone) = &instance.zone {
                            metadata.set_property("zone", zone.clone());
                        }
                        
                        // Machine Type
                        if let Some(machine_type) = &instance.machineType {
                            metadata.set_property("machine_type", machine_type.clone());
                        }
                        
                        // Status
                        if let Some(status) = &instance.status {
                            metadata.set_property("status", status.clone());
                        }
                        
                        // Creation Timestamp
                        if let Some(created) = &instance.creationTimestamp {
                            metadata.set_property("creation_timestamp", created.clone());
                        }
                        
                        // Network Interfaces
                        if let Some(nics) = &instance.networkInterfaces {
                            let mut subnet_urls = Vec::new();
                            let mut external_ips = Vec::new();
                            
                            for nic in nics {
                                if let Some(subnet) = &nic.subnetwork {
                                    subnet_urls.push(subnet.clone());
                                }
                                if let Some(access_configs) = &nic.accessConfigs {
                                    for ac in access_configs {
                                        if let Some(nat_ip) = &ac.natIP {
                                            external_ips.push(nat_ip.clone());
                                        }
                                    }
                                }
                            }
                            
                            if !subnet_urls.is_empty() {
                                metadata.set_property("subnetwork_urls", serde_json::to_string(&subnet_urls)?);
                            }
                            if !external_ips.is_empty() {
                                metadata.set_property("external_ips", serde_json::to_string(&external_ips)?);
                            }
                        }
                        
                        // Disks
                        if let Some(disks) = &instance.disks {
                            let boot_disks: Vec<String> = disks.iter()
                                .filter(|d| d.boot.unwrap_or(false))
                                .filter_map(|d| d.source.clone())
                                .collect();
                            
                            if !boot_disks.is_empty() {
                                metadata.set_property("boot_disk_sources", serde_json::to_string(&boot_disks)?);
                            }
                        }
                        
                        // Service Accounts
                        if let Some(service_accounts) = &instance.serviceAccounts {
                            let emails: Vec<String> = service_accounts.iter()
                                .filter_map(|sa| sa.email.clone())
                                .collect();
                            
                            if !emails.is_empty() {
                                metadata.set_property("service_account_emails", serde_json::to_string(&emails)?);
                            }
                            
                            // Check scopes for sensitive permissions
                            let has_sensitive_scope = service_accounts.iter()
                                .any(|sa| {
                                    sa.scopes.as_ref().map(|scopes| {
                                        scopes.iter().any(|s| {
                                            s.contains("/auth/cloud-platform") ||
                                            s.contains("/auth/compute")
                                        })
                                    }).unwrap_or(false)
                                });
                            
                            metadata.set_property("has_sensitive_scopes", has_sensitive_scope.to_string());
                        }
                        
                        // Labels
                        if let Some(labels) = &instance.labels {
                            for (key, value) in labels.iter() {
                                metadata.add_tag(Tag::new(key.clone(), value.clone()));
                            }
                        }

                        let resource = CloudResource::new(
                            format!("projects/{}/zones/{}/instances/{}", self.config.project_id, zone, instance_name),
                            instance_name.clone(),
                            ResourceType::VirtualMachine,
                            metadata,
                        );
                        
                        resources.push(resource);
                    }
                }
            }
        }

        Ok(resources)
    }

    /// Scan Cloud Storage Buckets
    #[instrument(skip(self))]
    async fn scan_storage_buckets(&self) -> Result<Vec<CloudResource>> {
        let http_client = self.http_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}",
            self.config.project_id
        );

        let auth_header = self.get_auth_header().await?;
        let response = http_client
            .get(&url)
            .header("Authorization", &auth_header)
            .send()
            .await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list buckets: {}", e)))?;

        if !response.status().is_success() {
            return Err(CloudGhidraError::ExternalServiceError(
                format!("Failed to fetch buckets: {}", response.status())
            ));
        }

        #[derive(Debug, Deserialize)]
        struct BucketListResponse {
            kind: Option<String>,
            items: Option<Vec<GcpBucket>>,
            nextPageToken: Option<String>,
        }

        let body: BucketListResponse = response
            .json()
            .await
            .map_err(|e| CloudGhidraError::ParseError(format!("Failed to parse buckets response: {}", e)))?;

        if let Some(buckets) = body.items {
            for bucket in buckets {
                if let Some(bucket_name) = &bucket.name {
                    let resource_id = bucket.id.clone().unwrap_or_default();
                    
                    let mut metadata = ResourceMetadata::new(CloudProvider::Gcp, ResourceType::ObjectStorage);
                    
                    // Location
                    if let Some(location) = &bucket.location {
                        metadata.set_property("location", location.clone());
                    }
                    
                    // Storage Class
                    if let Some(storage_class) = &bucket.storageClass {
                        metadata.set_property("storage_class", storage_class.clone());
                    }
                    
                    // Creation Time
                    if let Some(created) = &bucket.timeCreated {
                        metadata.set_property("creation_time", created.clone());
                    }
                    
                    // Encryption
                    if let Some(encryption) = &bucket.encryption {
                        if let Some(kms_key) = &encryption.defaultKmsKeyName {
                            metadata.set_property("encrypted", "true".to_string());
                            metadata.set_property("kms_key", kms_key.clone());
                        } else {
                            metadata.set_property("encrypted", "false".to_string());
                        }
                    }
                    
                    // Versioning
                    if let Some(versioning) = &bucket.versioning {
                        if let Some(enabled) = versioning.enabled {
                            metadata.set_property("versioning_enabled", enabled.to_string());
                        }
                    }
                    
                    // Uniform Bucket Level Access
                    if let Some(iam_config) = &bucket.iamConfiguration {
                        if let Some(ubla) = &iam_config.uniformBucketLevelAccess {
                            if let Some(enabled) = ubla.enabled {
                                metadata.set_property("uniform_bucket_level_access", enabled.to_string());
                            }
                        }
                    }
                    
                    // Labels
                    if let Some(labels) = &bucket.labels {
                        for (key, value) in labels.iter() {
                            metadata.add_tag(Tag::new(key.clone(), value.clone()));
                        }
                    }

                    let resource = CloudResource::new(
                        resource_id.clone(),
                        bucket_name.clone(),
                        ResourceType::ObjectStorage,
                        metadata,
                    );
                    
                    resources.push(resource);
                }
            }
        }

        Ok(resources)
    }

    /// Scan Cloud SQL Instances
    #[instrument(skip(self))]
    async fn scan_sql_instances(&self) -> Result<Vec<CloudResource>> {
        let http_client = self.http_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let url = format!(
            "https://sqladmin.googleapis.com/sql/v1beta4/projects/{}/instances",
            self.config.project_id
        );

        let auth_header = self.get_auth_header().await?;
        let response = http_client
            .get(&url)
            .header("Authorization", &auth_header)
            .send()
            .await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list SQL instances: {}", e)))?;

        if !response.status().is_success() {
            warn!("Failed to fetch SQL instances: {}", response.status());
            return Ok(resources);
        }

        #[derive(Debug, Deserialize)]
        struct SqlInstanceListResponse {
            kind: Option<String>,
            items: Option<Vec<GcpSqlInstance>>,
        }

        let body: SqlInstanceListResponse = response
            .json()
            .await
            .map_err(|e| CloudGhidraError::ParseError(format!("Failed to parse SQL instances response: {}", e)))?;

        if let Some(instances) = body.items {
            for instance in instances {
                if let Some(instance_name) = &instance.name {
                    let resource_id = format!(
                        "projects/{}/instances/{}",
                        self.config.project_id, instance_name
                    );
                    
                    let mut metadata = ResourceMetadata::new(CloudProvider::Gcp, ResourceType::Database);
                    
                    // Region
                    if let Some(region) = &instance.region {
                        metadata.set_property("region", region.clone());
                    }
                    
                    // Backend Type
                    if let Some(backend_type) = &instance.backendType {
                        metadata.set_property("backend_type", backend_type.clone());
                    }
                    
                    // Database Version
                    if let Some(db_version) = &instance.databaseVersion {
                        metadata.set_property("database_version", db_version.clone());
                    }
                    
                    // State
                    if let Some(state) = &instance.state {
                        metadata.set_property("state", state.clone());
                    }
                    
                    // Instance Type
                    if let Some(instance_type) = &instance.instanceType {
                        metadata.set_property("instance_type", instance_type.clone());
                    }
                    
                    // Settings
                    if let Some(settings) = &instance.settings {
                        // Tier
                        if let Some(tier) = &settings.tier {
                            metadata.set_property("tier", tier.clone());
                        }
                        
                        // Availability Type
                        if let Some(avail_type) = &settings.availabilityType {
                            metadata.set_property("availability_type", avail_type.clone());
                        }
                        
                        // Disk Size
                        if let Some(disk_size) = &settings.dataDiskSizeGb {
                            metadata.set_property("disk_size_gb", disk_size.clone());
                        }
                        
                        // Disk Type
                        if let Some(disk_type) = &settings.dataDiskType {
                            metadata.set_property("disk_type", disk_type.clone());
                        }
                        
                        // Auto Resize
                        if let Some(auto_resize) = &settings.storageAutoResize {
                            metadata.set_property("storage_auto_resize", auto_resize.to_string());
                        }
                        
                        // Backup Configuration
                        if let Some(backup_config) = &settings.backupConfiguration {
                            if let Some(enabled) = backup_config.enabled {
                                metadata.set_property("backup_enabled", enabled.to_string());
                            }
                            if let Some(pitr_enabled) = backup_config.pointInTimeRecoveryEnabled {
                                metadata.set_property("point_in_time_recovery", pitr_enabled.to_string());
                            }
                            if let Some(retention_days) = backup_config.transactionLogRetentionDays {
                                metadata.set_property("log_retention_days", retention_days.to_string());
                            }
                        }
                        
                        // IP Configuration
                        if let Some(ip_config) = &settings.ipConfiguration {
                            if let Some(ipv4_enabled) = ip_config.ipv4Enabled {
                                metadata.set_property("ipv4_enabled", ipv4_enabled.to_string());
                            }
                            if let Some(require_ssl) = ip_config.requireSsl {
                                metadata.set_property("require_ssl", require_ssl.to_string());
                            }
                            if let Some(private_network) = &ip_config.privateNetwork {
                                metadata.set_property("private_network", private_network.clone());
                            }
                        }
                        
                        // User Labels
                        if let Some(labels) = &settings.userLabels {
                            for (key, value) in labels.iter() {
                                metadata.add_tag(Tag::new(key.clone(), value.clone()));
                            }
                        }
                    }
                    
                    // IP Addresses
                    if let Some(ip_addresses) = &instance.ipAddresses {
                        let public_ips: Vec<String> = ip_addresses.iter()
                            .filter(|ip| ip.type_.as_ref().map(|t| t == "PRIMARY").unwrap_or(false))
                            .filter_map(|ip| ip.ipAddress.clone())
                            .collect();
                        
                        if !public_ips.is_empty() {
                            metadata.set_property("public_ip_addresses", serde_json::to_string(&public_ips)?);
                        }
                    }

                    let resource = CloudResource::new(
                        resource_id,
                        instance_name.clone(),
                        ResourceType::Database,
                        metadata,
                    );
                    
                    resources.push(resource);
                }
            }
        }

        Ok(resources)
    }

    /// Scan GKE Clusters
    #[instrument(skip(self))]
    async fn scan_gke_clusters(&self) -> Result<Vec<CloudResource>> {
        let http_client = self.http_client.as_ref().ok_or(CloudGhidraError::NotConnected)?;
        let mut resources = Vec::new();

        let url = format!(
            "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
            self.config.project_id
        );

        let auth_header = self.get_auth_header().await?;
        let response = http_client
            .get(&url)
            .header("Authorization", &auth_header)
            .send()
            .await
            .map_err(|e| CloudGhidraError::ExternalServiceError(format!("Failed to list GKE clusters: {}", e)))?;

        if !response.status().is_success() {
            warn!("Failed to fetch GKE clusters: {}", response.status());
            return Ok(resources);
        }

        #[derive(Debug, Deserialize)]
        struct ClusterListResponse {
            clusters: Option<Vec<GcpCluster>>,
        }

        let body: ClusterListResponse = response
            .json()
            .await
            .map_err(|e| CloudGhidraError::ParseError(format!("Failed to parse clusters response: {}", e)))?;

        if let Some(clusters) = body.clusters {
            for cluster in clusters {
                if let Some(cluster_name) = &cluster.name {
                    let resource_id = format!(
                        "projects/{}/locations/{}/clusters/{}",
                        self.config.project_id,
                        cluster.locations.as_ref().and_then(|l| l.first()).cloned().unwrap_or_else(|| "unknown".to_string()),
                        cluster_name
                    );
                    
                    let mut metadata = ResourceMetadata::new(CloudProvider::Gcp, ResourceType::ContainerCluster);
                    
                    // Description
                    if let Some(desc) = &cluster.description {
                        metadata.set_property("description", desc.clone());
                    }
                    
                    // Locations
                    if let Some(locations) = &cluster.locations {
                        metadata.set_property("locations", serde_json::to_string(locations)?);
                    }
                    
                    // Initial Node Count
                    if let Some(node_count) = &cluster.initialNodeCount {
                        metadata.set_property("initial_node_count", node_count.to_string());
                    }
                    
                    // Network
                    if let Some(network) = &cluster.network {
                        metadata.set_property("network", network.clone());
                    }
                    
                    // Subnetwork
                    if let Some(subnetwork) = &cluster.subnetwork {
                        metadata.set_property("subnetwork", subnetwork.clone());
                    }
                    
                    // Cluster IPv4 CIDR
                    if let Some(cidr) = &cluster.clusterIpv4Cidr {
                        metadata.set_property("cluster_ipv4_cidr", cidr.clone());
                    }
                    
                    // Logging Service
                    if let Some(logging) = &cluster.loggingService {
                        metadata.set_property("logging_service", logging.clone());
                    }
                    
                    // Monitoring Service
                    if let Some(monitoring) = &cluster.monitoringService {
                        metadata.set_property("monitoring_service", monitoring.clone());
                    }
                    
                    // Status
                    if let Some(status) = &cluster.status {
                        metadata.set_property("status", status.clone());
                    }
                    
                    // Endpoint
                    if let Some(endpoint) = &cluster.endpoint {
                        metadata.set_property("endpoint", endpoint.clone());
                    }
                    
                    // Initial Cluster Version
                    if let Some(init_version) = &cluster.initialClusterVersion {
                        metadata.set_property("initial_cluster_version", init_version.clone());
                    }
                    
                    // Current Master Version
                    if let Some(master_version) = &cluster.currentMasterVersion {
                        metadata.set_property("current_master_version", master_version.clone());
                    }
                    
                    // Current Node Version
                    if let Some(node_version) = &cluster.currentNodeVersion {
                        metadata.set_property("current_node_version", node_version.clone());
                    }
                    
                    // Creation Time
                    if let Some(create_time) = &cluster.createTime {
                        metadata.set_property("creation_time", create_time.clone());
                    }
                    
                    // Node Config
                    if let Some(node_config) = &cluster.nodeConfig {
                        if let Some(machine_type) = &node_config.machineType {
                            metadata.set_property("node_machine_type", machine_type.clone());
                        }
                        if let Some(disk_size) = &node_config.diskSizeGb {
                            metadata.set_property("node_disk_size_gb", disk_size.to_string());
                        }
                        if let Some(image_type) = &node_config.imageType {
                            metadata.set_property("node_image_type", image_type.clone());
                        }
                        if let Some(preemptible) = &node_config.preemptible {
                            metadata.set_property("node_preemptible", preemptible.to_string());
                        }
                        if let Some(service_account) = &node_config.serviceAccount {
                            metadata.set_property("node_service_account", service_account.clone());
                        }
                    }
                    
                    // Legacy ABAC
                    if let Some(legacy_abac) = &cluster.legacyAbac {
                        if let Some(enabled) = legacy_abac.enabled {
                            metadata.set_property("legacy_abac_enabled", enabled.to_string());
                        }
                    }
                    
                    // Binary Authorization
                    if let Some(bin_auth) = &cluster.binaryAuthorization {
                        if let Some(enabled) = bin_auth.enabled {
                            metadata.set_property("binary_authorization_enabled", enabled.to_string());
                        }
                    }
                    
                    // Workload Identity
                    if let Some(workload_identity) = &cluster.workloadIdentityConfig {
                        if let Some(pool) = &workload_identity.workloadPool {
                            metadata.set_property("workload_identity_pool", pool.clone());
                        }
                    }
                    
                    // Release Channel
                    if let Some(release_channel) = &cluster.releaseChannel {
                        if let Some(channel) = &release_channel.channel {
                            metadata.set_property("release_channel", channel.clone());
                        }
                    }
                    
                    // Resource Labels
                    if let Some(labels) = &cluster.resourceLabels {
                        for (key, value) in labels.iter() {
                            metadata.add_tag(Tag::new(key.clone(), value.clone()));
                        }
                    }

                    let resource = CloudResource::new(
                        resource_id,
                        cluster_name.clone(),
                        ResourceType::ContainerCluster,
                        metadata,
                    );
                    
                    resources.push(resource);
                }
            }
        }

        Ok(resources)
    }
}

#[async_trait]
impl CloudConnector for GcpConnector {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn is_connected(&self) -> bool {
        self.is_connected
    }

    async fn connect_async(&mut self) -> Result<()> {
        self.connect().await
    }

    async fn disconnect_async(&mut self) -> Result<()> {
        self.auth_manager = None;
        self.http_client = None;
        self.is_connected = false;
        info!("Disconnected from GCP");
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
            ResourceType::ContainerCluster,
            ResourceType::LoadBalancer,
            ResourceType::NetworkInterface,
            ResourceType::SecretManager,
        ]);

        if target_types.contains(&ResourceType::VirtualMachine) {
            match self.scan_compute_instances().await {
                Ok(resources) => {
                    info!("Scanned {} GCP Compute instances", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan GCP Compute instances: {}", e),
            }
        }

        if target_types.contains(&ResourceType::ObjectStorage) {
            match self.scan_storage_buckets().await {
                Ok(resources) => {
                    info!("Scanned {} GCS buckets", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan GCS buckets: {}", e),
            }
        }

        if target_types.contains(&ResourceType::Database) {
            match self.scan_sql_instances().await {
                Ok(resources) => {
                    info!("Scanned {} Cloud SQL instances", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan Cloud SQL instances: {}", e),
            }
        }

        if target_types.contains(&ResourceType::ContainerCluster) {
            match self.scan_gke_clusters().await {
                Ok(resources) => {
                    info!("Scanned {} GKE clusters", resources.len());
                    all_resources.extend(resources);
                },
                Err(e) => warn!("Failed to scan GKE clusters: {}", e),
            }
        }

        Ok(all_resources)
    }

    async fn validate_credentials(&self) -> Result<bool> {
        Ok(self.is_connected)
    }

    async fn get_metadata(&self) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "GCP".to_string());
        metadata.insert("project_id".to_string(), self.config.project_id.clone());
        metadata.insert("connected".to_string(), self.is_connected.to_string());
        if let Some(region) = &self.config.region {
            metadata.insert("region".to_string(), region.clone());
        }
        metadata.insert("zones".to_string(), serde_json::to_string(&self.config.zones)?);
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gcp_connector_creation() {
        let connector = GcpConnector::new();
        assert_eq!(connector.provider(), CloudProvider::Gcp);
        assert!(!connector.is_connected());
    }

    #[tokio::test]
    async fn test_gcp_connector_config() {
        let config = GcpConnectorConfig {
            project_id: "my-gcp-project".to_string(),
            region: Some("europe-west1".to_string()),
            zones: vec!["europe-west1-a".to_string(), "europe-west1-b".to_string()],
            ..Default::default()
        };
        let connector = GcpConnector::with_config(config);
        assert_eq!(connector.provider(), CloudProvider::Gcp);
    }
}
