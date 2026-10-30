
import pytest

from app.core.config import get_settings


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("APP_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("APP_WORKSPACE_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv("APP_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("MODEL_MOCK_MODE", "true")
    monkeypatch.setenv("OTEL_TRACES_ENABLED", "false")
    monkeypatch.setenv("OTEL_METRICS_ENABLED", "false")
    get_settings.cache_clear()

    import app.persistence.db as db_module

    db_module._engine = None
    db_module._session_factory = None

    yield tmp_path

    get_settings.cache_clear()
    db_module._engine = None
    db_module._session_factory = None
