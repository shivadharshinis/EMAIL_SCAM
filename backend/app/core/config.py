from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Email Threat Detection Platform"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    frontend_origin: str = "http://localhost:5173"

    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_password: str = "changeme"
    mysql_database: str = "email_threat_intel"

    max_email_bytes: int = 5 * 1024 * 1024
    passive_intel_enabled: bool = False
    passive_intel_provider: str = "rdap"
    passive_intel_timeout_seconds: float = 3.0
    passive_intel_max_lookups: int = 20
    ipapi_is_api_key: str = ""
    jwt_secret_key: str = "development-only-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    report_auth_required: bool = False
    demo_username: str = "analyst"
    demo_password: str = "change-me"

    @property
    def database_url(self) -> str:
        return (
            f"mysql+pymysql://{self.mysql_user}:{self.mysql_password}"
            f"@{self.mysql_host}:{self.mysql_port}/{self.mysql_database}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
