"""Environment-driven application configuration using Pydantic Settings v2."""

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_DEV_JWT_SECRET = (
    "aegis-dev-jwt-secret-key-do-not-use-in-production-64chars-minimum-001"
)
_DEFAULT_DEV_MASTER_KEY = (
    "aegis-dev-master-key-change-in-production-32bytes-9f8a7b6c5d4e3f"
)
_INSECURE_KNOWN_SECRETS = {
    _DEFAULT_DEV_JWT_SECRET,
    _DEFAULT_DEV_MASTER_KEY,
    "change-this-in-production-to-a-64-char-high-entropy-secret-key-01",
    "changeme",
    "secret",
    "password",
}
_NON_PRODUCTION_ENVS = {"development", "dev", "test", "testing", "local"}


class Settings(BaseSettings):
    """Centralized configuration for the AegisAI backend."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Application Settings
    aegis_env: str = Field(default="development", alias="AEGIS_ENV")
    aegis_app_name: str = Field(
        default="AegisAI Security Assessment Platform", alias="AEGIS_APP_NAME"
    )
    aegis_api_v1_prefix: str = Field(default="/api/v1", alias="AEGIS_API_V1_PREFIX")
    aegis_log_level: str = Field(default="INFO", alias="AEGIS_LOG_LEVEL")

    # Database & Queue
    database_url: str = Field(
        default="sqlite:///./aegis_local.db", alias="DATABASE_URL"
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    aegis_runner_mode: str = Field(default="in_process", alias="AEGIS_RUNNER_MODE")

    # Authentication & JWT
    aegis_jwt_secret_key: str = Field(
        default=_DEFAULT_DEV_JWT_SECRET,
        alias="AEGIS_JWT_SECRET_KEY",
    )
    aegis_jwt_algorithm: str = Field(default="HS256", alias="AEGIS_JWT_ALGORITHM")
    aegis_access_token_expire_minutes: int = Field(
        default=480, alias="AEGIS_ACCESS_TOKEN_EXPIRE_MINUTES"
    )

    # Envelope Encryption Master Key
    aegis_master_encryption_key: str = Field(
        default=_DEFAULT_DEV_MASTER_KEY,
        alias="AEGIS_MASTER_ENCRYPTION_KEY",
    )

    @model_validator(mode="after")
    def _validate_security_secrets(self) -> "Settings":
        jwt_secret = (self.aegis_jwt_secret_key or "").strip()
        master_key = (self.aegis_master_encryption_key or "").strip()

        if not jwt_secret:
            raise ValueError("AEGIS_JWT_SECRET_KEY must not be empty.")
        if not master_key:
            raise ValueError("AEGIS_MASTER_ENCRYPTION_KEY must not be empty.")

        env_norm = (self.aegis_env or "development").strip().lower()
        if env_norm not in _NON_PRODUCTION_ENVS:
            jwt_lower = jwt_secret.lower()
            if (
                jwt_secret in _INSECURE_KNOWN_SECRETS
                or len(jwt_secret) < 32
                or "do-not-use-in-production" in jwt_lower
                or "change-in-production" in jwt_lower
                or "change-this-in-production" in jwt_lower
            ):
                raise ValueError(
                    "AEGIS_JWT_SECRET_KEY uses an insecure default or insufficient length for a "
                    f"'{self.aegis_env}' environment. Configure an explicit high-entropy secret (>= 32 chars)."
                )

            master_lower = master_key.lower()
            if (
                master_key in _INSECURE_KNOWN_SECRETS
                or len(master_key) < 32
                or "do-not-use-in-production" in master_lower
                or "change-in-production" in master_lower
                or "change-this-in-production" in master_lower
            ):
                raise ValueError(
                    "AEGIS_MASTER_ENCRYPTION_KEY uses an insecure default or insufficient length for a "
                    f"'{self.aegis_env}' environment. Configure an explicit high-entropy master key (>= 32 chars)."
                )

        return self

    # SSRF & Outbound Request Safety Budgets
    aegis_allow_isolated_local_targets: bool = Field(
        default=False, alias="AEGIS_ALLOW_ISOLATED_LOCAL_TARGETS"
    )
    aegis_allowed_local_hosts: str = Field(
        default="localhost,127.0.0.1,target-sim", alias="AEGIS_ALLOWED_LOCAL_HOSTS"
    )
    aegis_default_max_rps: float = Field(
        default=2.0, alias="AEGIS_DEFAULT_MAX_RPS", gt=0.0, le=50.0
    )
    aegis_default_request_timeout_seconds: int = Field(
        default=15, alias="AEGIS_DEFAULT_REQUEST_TIMEOUT_SECONDS", ge=1, le=120
    )
    aegis_max_response_bytes: int = Field(
        default=524288, alias="AEGIS_MAX_RESPONSE_BYTES", ge=4096
    )
    aegis_max_requests_per_assessment: int = Field(
        default=50, alias="AEGIS_MAX_REQUESTS_PER_ASSESSMENT", ge=1, le=500
    )

    # CORS Configuration
    aegis_cors_origins: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000",
        alias="AEGIS_CORS_ORIGINS",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.aegis_cors_origins.split(",")
            if origin.strip()
        ]

    @property
    def allowed_local_hosts_set(self) -> set[str]:
        return {
            host.strip().lower()
            for host in self.aegis_allowed_local_hosts.split(",")
            if host.strip()
        }


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
