from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.db import Database
from app.main import create_app
from app.orchestrator import AssessmentManager


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(root_dir=Path.cwd(), data_dir=tmp_path / "data")


@pytest.fixture
def database(settings: Settings) -> Database:
    return Database(settings.db_path)


@pytest.fixture
def manager(database: Database, settings: Settings) -> AssessmentManager:
    return AssessmentManager(database, settings)


@pytest.fixture
def application(settings: Settings):
    return create_app(settings)
