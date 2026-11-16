"""Network flow scoring with the trained detector."""

import logging
import threading
from dataclasses import dataclass
from typing import Annotated, Any

import pandas as pd
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, create_model

from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.core.responses import Envelope, ok
from app.ml.inference import DECISION_THRESHOLD, attack_probabilities, unseen_categories
from app.ml.persistence import LoadedModel, ModelUnavailableError, load_model
from app.ml.schema import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES

logger = logging.getLogger("sentinelx.model")

router = APIRouter(prefix="/api/v1/network", tags=["network"])

MAX_FLOWS_PER_REQUEST = 100
_MAX_CATEGORY_LENGTH = 32
# Below the float32 maximum (about 3.4e38), which is what the forest reads values as.
_MAX_FEATURE_VALUE = 3.0e38
_MODEL_STATE_KEY = "network_model"
_load_lock = threading.Lock()

_Category = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=_MAX_CATEGORY_LENGTH)
]

_flow_fields: dict[str, Any] = {
    **{name: (_Category, ...) for name in CATEGORICAL_FEATURES},
    # Counts, sizes, rates and durations; the published data has no negatives.
    **{
        name: (float, Field(strict=True, ge=0, le=_MAX_FEATURE_VALUE, allow_inf_nan=False))
        for name in NUMERIC_FEATURES
    },
}

FlowFeatures = create_model(
    "FlowFeatures",
    __config__=ConfigDict(extra="forbid"),
    __doc__="One network flow described by the 42 features of the UNSW-NB15 training files.",
    **_flow_fields,
)


class ScoreRequest(BaseModel):
    flows: list[FlowFeatures] = Field(min_length=1, max_length=MAX_FLOWS_PER_REQUEST)  # type: ignore[valid-type]


class ScoredFlow(BaseModel):
    attack_probability: float
    is_attack: bool
    # Categorical values the model never saw in training; it scores them as rare.
    unseen_categories: list[str]


class ModelMetrics(BaseModel):
    """Measured on the dataset's own testing split when the model was trained."""

    precision: float
    recall: float
    f1: float
    accuracy: float
    false_positive_rate: float
    test_rows: int
    test_attack_share: float


class ModelInfo(BaseModel):
    name: str
    trained_at: str
    training_rows: int
    test_metrics: ModelMetrics


class ScoreResult(BaseModel):
    model: ModelInfo
    threshold: float
    scores: list[ScoredFlow]


@dataclass(frozen=True)
class _ServedModel:
    loaded: LoadedModel
    info: ModelInfo


def _read_served_model(settings: Settings) -> _ServedModel:
    try:
        loaded = load_model(settings.model_dir)
        metadata = loaded.metadata
        info = ModelInfo(
            name=metadata.model_name,
            trained_at=metadata.trained_at,
            training_rows=metadata.training_rows,
            test_metrics=ModelMetrics.model_validate(metadata.test_metrics),
        )
    except ModelUnavailableError as error:
        logger.warning("Model unavailable: %s", error)
        raise AppError("model_unavailable", error.public_message, status_code=503) from error
    except ValidationError as error:
        logger.warning("Model metadata has unexpected metrics: %s", error)
        raise AppError(
            "model_unavailable",
            "The stored model cannot be used. Retrain it with `python -m app.ml.train`.",
            status_code=503,
        ) from error
    # One thread per prediction: requests already run in parallel worker threads.
    loaded.pipeline.set_params(model__n_jobs=1)
    return _ServedModel(loaded=loaded, info=info)


def _served_model(request: Request, settings: Settings) -> _ServedModel:
    """Loads the saved model on first use and keeps it for later requests."""
    state = request.app.state
    served = getattr(state, _MODEL_STATE_KEY, None)
    if served is None:
        with _load_lock:
            served = getattr(state, _MODEL_STATE_KEY, None)
            if served is None:
                served = _read_served_model(settings)
                setattr(state, _MODEL_STATE_KEY, served)
    return served


@router.post("/score")
def score_flows(
    body: ScoreRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Envelope[ScoreResult]:
    """Scores flows from a network you own or are authorised to inspect."""
    served = _served_model(request, settings)
    pipeline = served.loaded.pipeline
    features = pd.DataFrame([flow.model_dump() for flow in body.flows])[list(FEATURE_COLUMNS)]
    probabilities = attack_probabilities(pipeline, features)
    unseen = unseen_categories(pipeline, features)
    return ok(
        ScoreResult(
            model=served.info,
            threshold=DECISION_THRESHOLD,
            scores=[
                ScoredFlow(
                    attack_probability=float(probability),
                    is_attack=bool(probability >= DECISION_THRESHOLD),
                    unseen_categories=names,
                )
                for probability, names in zip(probabilities, unseen, strict=True)
            ],
        )
    )
