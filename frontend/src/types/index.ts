/**
 * Strict TypeScript contracts mirroring AegisAI Backend Pydantic v2 schemas.
 */

export type RoleEnum = "ORG_ADMIN" | "SECURITY_ENGINEER" | "VIEWER";

export type ArchitectureTypeEnum =
  | "LLM_APP"
  | "RAG_PIPELINE"
  | "AI_AGENT"
  | "HYBRID";

export type IntegrationModeEnum =
  | "BLACK_BOX_REST"
  | "OPENAI_COMPAT"
  | "ASSISTED_HARNESS"
  | "CONFIG_ONLY"
  | "SIMULATOR";

export type AuthTypeEnum =
  | "NONE"
  | "BEARER_TOKEN"
  | "API_KEY_HEADER"
  | "DUAL_TENANT_BEARER";

export type AssessmentStatusEnum =
  | "DRAFT"
  | "QUEUED"
  | "PROFILING"
  | "ANALYZING_ARCHITECTURE"
  | "EXECUTING_TESTS"
  | "EVALUATING"
  | "COMPLETED"
  | "FAILED";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  max_rps_limit: number;
  created_at: string;
}

export interface User {
  id: string;
  organization_id: string;
  email: string;
  full_name: string;
  role: RoleEnum;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user: User;
  organization: Organization;
}

export interface TargetProfile {
  id: string;
  organization_id: string;
  name: string;
  architecture_type: ArchitectureTypeEnum;
  integration_mode: IntegrationModeEnum;
  endpoint_url: string;
  allowed_hosts: string[];
  auth_type: AuthTypeEnum;
  credential_preview?: string | null;
  request_template: Record<string, unknown>;
  architecture_manifest: Record<string, unknown>;
  rag_harness_config?: Record<string, unknown> | null;
  agent_harness_config?: Record<string, unknown> | null;
  rate_limit_rps: number;
  timeout_seconds: number;
  created_at: string;
}

export interface PlatformHealth {
  status: string;
  service: string;
  version: string;
  environment: string;
  runner_mode: string;
  database_connected: boolean;
}
