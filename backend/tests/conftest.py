from collections.abc import Callable
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.ml.schema import (
    ATTACK_CATEGORY_COLUMN,
    ID_COLUMN,
    LABEL_COLUMN,
    NORMAL_CATEGORY,
    NUMERIC_FEATURES,
)


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    """Builds settings isolated from any local `.env` file."""

    def _make(**overrides: object) -> Settings:
        return Settings(_env_file=None, app_env="test", **overrides)

    return _make


@pytest.fixture
def data_dir() -> Path:
    """Location of the locally downloaded datasets, which may be absent."""
    return Settings(_env_file=None).data_dir


@pytest.fixture
def make_flows() -> Callable[..., pd.DataFrame]:
    """Builds synthetic rows shaped like the UNSW-NB15 split files."""

    def _make(rows: int = 50, **columns: object) -> pd.DataFrame:
        rng = np.random.default_rng(seed=7)
        labels = np.asarray(columns.get(LABEL_COLUMN, rng.integers(0, 2, size=rows)))
        generated = {
            ID_COLUMN: np.arange(1, rows + 1),
            "proto": rng.choice(["tcp", "udp", "arp"], size=rows),
            "service": rng.choice(["-", "dns", "http"], size=rows),
            "state": rng.choice(["FIN", "INT", "CON"], size=rows),
            **{name: rng.integers(0, 1000, size=rows) for name in NUMERIC_FEATURES},
            "dur": rng.random(rows),
            ATTACK_CATEGORY_COLUMN: np.where(labels == 0, NORMAL_CATEGORY, "Generic"),
            LABEL_COLUMN: labels,
        }
        return pd.DataFrame({**generated, **columns})

    return _make


@pytest.fixture
def app(make_settings: Callable[..., Settings]) -> FastAPI:
    return create_app(make_settings())


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)
