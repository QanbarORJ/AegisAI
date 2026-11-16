"""Module C: AI Agent Security Scanner Plugins package."""

from app.engine.scanners.agent.plugins import (
    AgentGoalHijackingTest,
    ExcessiveAgencyAndToolSchemaAuditTest,
    UnauthorizedToolInvocationTest,
)

__all__ = [
    "AgentGoalHijackingTest",
    "ExcessiveAgencyAndToolSchemaAuditTest",
    "UnauthorizedToolInvocationTest",
]
