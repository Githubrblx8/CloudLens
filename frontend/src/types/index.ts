export interface CloudResource {
  id: string;
  arn: string;
  name: string;
  resource_type: string;
  provider: string;
  region?: string;
  metadata: Record<string, unknown>;
  tags: Record<string, string>;
  created_at?: string;
  updated_at?: string;
  is_public: boolean;
  encryption_status: 'enabled' | 'disabled' | 'partial' | 'unknown';
}

export interface ResourceRelationship {
  source_id: string;
  target_id: string;
  relationship_type: string;
  description: string;
  metadata: Record<string, unknown>;
}

export interface SecurityRisk {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  affected_resources: string[];
  recommendation: string;
  cwe_id?: string;
  mitre_attack_id?: string;
  detected_at: string;
  metadata: Record<string, unknown>;
}

export interface AccessPath {
  id: string;
  start_resource: string;
  end_resource: string;
  steps: AccessPathStep[];
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
}

export interface AccessPathStep {
  from_resource: string;
  to_resource: string;
  action: string;
  permission: string;
  description: string;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  affected_resources: string[];
}

export interface GraphNode {
  id: string;
  name: string;
  resource_type: string;
  provider: string;
  is_public: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship_type: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AnalysisSummary {
  total_resources: number;
  total_relationships: number;
  public_resources: number;
  unencrypted_resources: number;
  total_risks: number;
  critical_risks: number;
  high_risks: number;
  medium_risks: number;
  low_risks: number;
  risk_score: number;
}

export interface AnalysisReport {
  report_id: string;
  generated_at: string;
  completed_at: string;
  summary: AnalysisSummary;
  risks: SecurityRisk[];
  iam_findings: IAMFinding[];
  privilege_escalation_paths: AccessPath[];
  overly_permissive_identities: OverlyPermissiveIdentity[];
  graph_export: GraphData;
  recommendations: Recommendation[];
}

export interface IAMFinding {
  policy_name: string;
  finding_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  recommendation: string;
}

export interface OverlyPermissiveIdentity {
  identity_id: string;
  identity_name: string;
  identity_type: string;
  issues: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

export interface ResourceStats {
  total_resources: number;
  total_relationships: number;
  public_resources: number;
  unencrypted_resources: number;
  resource_types: Record<string, number>;
}

export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const RISK_SEVERITY_ORDER: Record<RiskSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const RISK_SEVERITY_COLORS: Record<RiskSeverity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6',
};

export const RESOURCE_TYPE_COLORS: Record<string, string> = {
  VM: '#3b82f6',
  Container: '#8b5cf6',
  Pod: '#a855f7',
  Bucket: '#f59e0b',
  Database: '#ef4444',
  VPC: '#10b981',
  Subnet: '#14b8a6',
  SecurityGroup: '#06b6d4',
  LoadBalancer: '#0ea5e9',
  User: '#ec4899',
  Group: '#d946ef',
  Role: '#8b5cf6',
  Policy: '#6366f1',
  Default: '#6b7280',
};
