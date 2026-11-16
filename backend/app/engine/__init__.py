"""AegisAI Modular Security Assessment Engine."""

import app.engine.scanners  # noqa: F401 - register all built-in scanner plugins
from app.engine.config_analyzer import ConfigurationAnalyzer
from app.engine.contracts import (
    ArchitectureAnalysisResult,
    BaseSecurityTest,
    ConfidenceLevel,
    ExecutionStatus,
    NormalizedTestResult,
    ScannerModule,
    SeverityLevel,
    StandardizedTargetResponse,
    TargetProfileResult,
    TechnicalEvidenceItem,
    TestContext,
    VulnerabilityStatus,
)
from app.engine.evidence import (
    EvidenceCollector,
    detect_and_mask_sensitive_artifacts,
    redact_headers,
    redact_string,
    sanitize_payload,
)
from app.engine.framework_mapper import (
    FrameworkMappingEngine,
    ImmutableFrameworkVersionError,
    KnowledgeBaseLoader,
    MappingRelationshipType,
    ensure_knowledge_base_seeded,
    load_authoritative_framework_bundles,
)
from app.engine.orchestrator import (
    AssessmentOrchestrator,
    compute_avss_v1,
    compute_posture_grade,
)
from app.engine.profiler import TargetProfiler
from app.engine.registry import (
    SecurityTestRegistry,
    default_registry,
    register_security_test,
)
from app.engine.remediation_engine import RemediationEngine
from app.engine.report_generator import ReportGenerator
from app.engine.risk_engine import RiskAssessmentEngine

__all__ = [
    "ArchitectureAnalysisResult",
    "AssessmentOrchestrator",
    "BaseSecurityTest",
    "ConfidenceLevel",
    "ConfigurationAnalyzer",
    "EvidenceCollector",
    "ExecutionStatus",
    "FrameworkMappingEngine",
    "ImmutableFrameworkVersionError",
    "KnowledgeBaseLoader",
    "MappingRelationshipType",
    "NormalizedTestResult",
    "RemediationEngine",
    "ReportGenerator",
    "RiskAssessmentEngine",
    "ScannerModule",
    "SecurityTestRegistry",
    "SeverityLevel",
    "StandardizedTargetResponse",
    "TargetProfileResult",
    "TargetProfiler",
    "TechnicalEvidenceItem",
    "TestContext",
    "VulnerabilityStatus",
    "compute_avss_v1",
    "compute_posture_grade",
    "default_registry",
    "detect_and_mask_sensitive_artifacts",
    "ensure_knowledge_base_seeded",
    "load_authoritative_framework_bundles",
    "redact_headers",
    "redact_string",
    "register_security_test",
    "sanitize_payload",
]
