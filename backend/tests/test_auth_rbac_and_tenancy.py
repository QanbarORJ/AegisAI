"""Phase 2 Verification: FastAPI Health, JWT Auth, RBAC Enforcement, and Multi-Tenant Isolation (IDOR Prevention)."""

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import RoleEnum, create_access_token
from app.models.target import TargetProfile


def test_health_endpoints(client: TestClient) -> None:
    """Verify both /health and /api/v1/health return 200 OK and active DB connectivity."""
    for path in ("/health", "/api/v1/health"):
        resp = client.get(path)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["database_connected"] is True
        assert body["version"] == "0.2.0"


def test_register_organization_login_and_me_workflow(client: TestClient) -> None:
    """Verify organization bootstrap registration, login, duplicate conflict handling, and /auth/me."""
    reg_payload = {
        "organization_name": "CyberSentinel AI Lab",
        "organization_slug": "cybersentinel-lab",
        "email": "founder@cybersentinel.io",
        "full_name": "Ada Lovelace",
        "password": "StrongFounderPassword!2026",
    }
    reg_resp = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_resp.status_code == 201
    data = reg_resp.json()
    assert data["access_token"]
    assert data["user"]["role"] == "ORG_ADMIN"
    assert data["organization"]["slug"] == "cybersentinel-lab"

    # Duplicate slug or email must return 409 CONFLICT
    dup_resp = client.post("/api/v1/auth/register", json=reg_payload)
    assert dup_resp.status_code == 409
    assert dup_resp.json()["error"]["code"] == "ORGANIZATION_SLUG_CONFLICT"

    # Login with valid credentials
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "founder@cybersentinel.io", "password": "StrongFounderPassword!2026"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Login with wrong password returns 401
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"email": "founder@cybersentinel.io", "password": "WrongPassword"},
    )
    assert bad_login.status_code == 401
    assert bad_login.json()["error"]["code"] == "AUTHENTICATION_FAILED"

    # /api/v1/auth/me returns authenticated user profile
    me_resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "founder@cybersentinel.io"


def test_expired_and_missing_jwt_rejected(
    client: TestClient, multi_tenant_seed: dict[str, object]
) -> None:
    """Verify missing, malformed, and expired JWT tokens return 401 AUTHENTICATION_FAILED."""
    assert client.get("/api/v1/auth/me").status_code == 401
    assert (
        client.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer invalid.jwt.token"}
        ).status_code
        == 401
    )

    alpha_admin = multi_tenant_seed["alpha_admin"]
    org_alpha = multi_tenant_seed["org_alpha"]
    expired_token = create_access_token(
        user_id=alpha_admin.id,
        organization_id=org_alpha.id,
        email=alpha_admin.email,
        role=RoleEnum.ORG_ADMIN,
        expires_delta=timedelta(minutes=-5),
    )
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["error"]["message"].lower()


def test_rbac_role_enforcement(
    client: TestClient, multi_tenant_seed: dict[str, object]
) -> None:
    """Verify ORG_ADMIN, SECURITY_ENGINEER, and VIEWER permissions across user, audit, and target endpoints."""
    tokens: dict[str, str] = multi_tenant_seed["tokens"]  # type: ignore[assignment]

    new_user_payload = {
        "email": "new.analyst@alpha.example.com",
        "full_name": "New Analyst",
        "password": "AnalystPassword123!",
        "role": "VIEWER",
    }

    # SECURITY_ENGINEER and VIEWER cannot provision users (403 FORBIDDEN_OPERATION)
    for role_key in ("alpha_engineer", "alpha_viewer"):
        resp = client.post(
            "/api/v1/auth/users",
            json=new_user_payload,
            headers={"Authorization": f"Bearer {tokens[role_key]}"},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN_OPERATION"

    # ORG_ADMIN can provision users (201 CREATED) and inspect audit logs (200 OK)
    admin_resp = client.post(
        "/api/v1/auth/users",
        json=new_user_payload,
        headers={"Authorization": f"Bearer {tokens['alpha_admin']}"},
    )
    assert admin_resp.status_code == 201

    audit_resp = client.get(
        "/api/v1/auth/audit-logs",
        headers={"Authorization": f"Bearer {tokens['alpha_admin']}"},
    )
    assert audit_resp.status_code == 200
    assert len(audit_resp.json()) >= 1

    # SECURITY_ENGINEER cannot view org-wide audit logs
    eng_audit = client.get(
        "/api/v1/auth/audit-logs",
        headers={"Authorization": f"Bearer {tokens['alpha_engineer']}"},
    )
    assert eng_audit.status_code == 403

    # VIEWER cannot create or inspect TargetProfiles (SECURITY_DESIGN.md Section 5)
    target_payload = {
        "name": "Alpha Customer Support Bot",
        "architecture_type": "RAG_PIPELINE",
        "integration_mode": "SIMULATOR",
        "endpoint_url": "https://sim.alpha.example/v1/chat",
        "allowed_hosts": ["sim.alpha.example"],
        "auth_type": "BEARER_TOKEN",
        "credentials": {"api_key": "sk-proj-alphatargetsecretkey987654"},
    }
    viewer_target_resp = client.post(
        "/api/v1/targets",
        json=target_payload,
        headers={"Authorization": f"Bearer {tokens['alpha_viewer']}"},
    )
    assert viewer_target_resp.status_code == 403


def test_multi_tenant_isolation_and_target_ssrf_enforcement(
    client: TestClient,
    db_session: Session,
    multi_tenant_seed: dict[str, object],
) -> None:
    """Verify strict tenant isolation (IDOR prevention), encrypted credential storage, and SSRF guard on TargetProfiles."""
    tokens: dict[str, str] = multi_tenant_seed["tokens"]  # type: ignore[assignment]

    # 1. Alpha SECURITY_ENGINEER creates a TargetProfile with credentials
    create_resp = client.post(
        "/api/v1/targets",
        json={
            "name": "Alpha RAG Assistant",
            "architecture_type": "RAG_PIPELINE",
            "integration_mode": "SIMULATOR",
            "endpoint_url": "https://rag.alpha.example.com/v1/query",
            "allowed_hosts": ["rag.alpha.example.com"],
            "auth_type": "BEARER_TOKEN",
            "credentials": {"api_key": "sk-proj-alphaprodsecretkey11223344"},
        },
        headers={"Authorization": f"Bearer {tokens['alpha_engineer']}"},
    )
    assert create_resp.status_code == 201
    target_data = create_resp.json()
    target_id = target_data["id"]

    # API response must never expose plaintext or raw encrypted_credentials; only masked preview
    assert "encrypted_credentials" not in target_data
    assert "sk-proj-alphaprodsecretkey11223344" not in str(target_data)
    assert target_data["credential_preview"] == "sk-pro****...3344"

    # Verify in DB that credentials are encrypted with v1: AES-256-GCM envelope
    db_target = db_session.query(TargetProfile).filter(TargetProfile.id == target_id).first()
    assert db_target is not None
    assert db_target.encrypted_credentials is not None
    assert db_target.encrypted_credentials.startswith("v1:")
    assert "sk-proj-alphaprodsecretkey11223344" not in db_target.encrypted_credentials

    # 2. Cross-tenant IDOR attempt: Beta ORG_ADMIN tries to fetch Alpha's target_id -> 404 TENANT_SCOPE_VIOLATION
    idor_resp = client.get(
        f"/api/v1/targets/{target_id}",
        headers={"Authorization": f"Bearer {tokens['beta_admin']}"},
    )
    assert idor_resp.status_code == 404
    assert idor_resp.json()["error"]["code"] == "TENANT_SCOPE_VIOLATION"

    # Beta listing targets sees 0 records
    beta_list = client.get(
        "/api/v1/targets",
        headers={"Authorization": f"Bearer {tokens['beta_admin']}"},
    )
    assert beta_list.status_code == 200
    assert beta_list.json() == []

    # 3. Attempting to register a TargetProfile pointing to 169.254.169.254 or 127.0.0.1 is blocked with 422 SSRF_BOUNDARY_BLOCKED
    ssrf_resp = client.post(
        "/api/v1/targets",
        json={
            "name": "Malicious SSRF Target",
            "architecture_type": "LLM_APP",
            "integration_mode": "SIMULATOR",
            "endpoint_url": "http://169.254.169.254/latest/meta-data/iam/",
            "allowed_hosts": ["169.254.169.254"],
            "auth_type": "NONE",
        },
        headers={"Authorization": f"Bearer {tokens['alpha_engineer']}"},
    )
    assert ssrf_resp.status_code == 422
    assert ssrf_resp.json()["error"]["code"] == "SSRF_BOUNDARY_BLOCKED"
