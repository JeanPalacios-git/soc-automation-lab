"""
Application configuration.

Loads application settings from environment variables.
"""

from dataclasses import dataclass
import os

from dotenv import load_dotenv


# Load variables from the .env file into the environment
load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Application configuration."""

    host: str = os.getenv("WAZUH_HOST", "")
    port: int = int(os.getenv("WAZUH_PORT", "55000"))

    username: str = os.getenv("WAZUH_USERNAME", "")
    password: str = os.getenv("WAZUH_PASSWORD", "")

    verify_ssl: bool = (
        os.getenv("VERIFY_SSL", "false").lower() == "true"
    )

    timeout: int = int(os.getenv("REQUEST_TIMEOUT", "30"))


settings = Settings()