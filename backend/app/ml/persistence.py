"""Saving and loading the trained detector.

The model is stored with joblib, which uses pickle: only load artifacts this
project produced itself, never a file from an untrusted source. The checksum in
the metadata detects a model file paired with the wrong metadata or damaged on
disk; it does not protect against someone who can write to the folder.
"""

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import joblib
import sklearn
from sklearn.pipeline import Pipeline

from app.ml.schema import FEATURE_COLUMNS

MODEL_FILENAME = "model.joblib"
METADATA_FILENAME = "model.json"

_TRAIN_HINT = "Train one with `python -m app.ml.train` (see 'Dataset' in the README)."
_NOT_FOUND_MESSAGE = "No trained model is available. Train one with `python -m app.ml.train`."
_UNUSABLE_MESSAGE = "The stored model cannot be used. Retrain it with `python -m app.ml.train`."
_COMPRESSION_LEVEL = 3
_CHUNK_BYTES = 1024 * 1024


class ModelUnavailableError(RuntimeError):
    """No usable trained model is available.

    `str(error)` is the full detail for server logs and may name paths or
    versions; `public_message` is safe to show to a client.
    """

    def __init__(self, detail: str, public_message: str = _UNUSABLE_MESSAGE) -> None:
        super().__init__(detail)
        self.public_message = public_message


@dataclass(frozen=True)
class ModelMetadata:
    """What a stored model is and how it scored, kept next to the model file."""

    model_name: str
    trained_at: str
    training_rows: int
    feature_columns: list[str]
    sklearn_version: str
    test_metrics: dict[str, float]
    # Filled in by `save_model`; checked on load.
    model_sha256: str = ""


@dataclass(frozen=True)
class LoadedModel:
    pipeline: Pipeline
    metadata: ModelMetadata


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _replace_atomically(target: Path, write: Callable[[Path], None]) -> None:
    """Writes beside the target, then swaps it in, so readers never see half a file."""
    temporary = target.with_name(f"{target.name}.tmp")
    write(temporary)
    os.replace(temporary, target)


def save_model(directory: Path, pipeline: Pipeline, metadata: ModelMetadata) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    model_path = directory / MODEL_FILENAME
    _replace_atomically(
        model_path, lambda path: joblib.dump(pipeline, path, compress=_COMPRESSION_LEVEL)
    )
    stored = replace(metadata, model_sha256=_file_sha256(model_path))
    _replace_atomically(
        directory / METADATA_FILENAME,
        lambda path: path.write_text(json.dumps(asdict(stored), indent=2), encoding="utf-8"),
    )


def _read_metadata(directory: Path) -> ModelMetadata:
    path = directory / METADATA_FILENAME
    if not path.is_file() or not (directory / MODEL_FILENAME).is_file():
        raise ModelUnavailableError(
            f"No trained model found in {directory}. {_TRAIN_HINT}", _NOT_FOUND_MESSAGE
        )
    try:
        return ModelMetadata(**json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as error:
        raise ModelUnavailableError(
            f"The model metadata in {directory} is unreadable. {_TRAIN_HINT}"
        ) from error


def _check_compatible(directory: Path, metadata: ModelMetadata) -> None:
    if metadata.sklearn_version != sklearn.__version__:
        raise ModelUnavailableError(
            f"The stored model was built with scikit-learn {metadata.sklearn_version} but "
            f"{sklearn.__version__} is installed. {_TRAIN_HINT}"
        )
    if metadata.feature_columns != list(FEATURE_COLUMNS):
        raise ModelUnavailableError(
            f"The stored model expects a different feature layout. {_TRAIN_HINT}"
        )
    if _file_sha256(directory / MODEL_FILENAME) != metadata.model_sha256:
        raise ModelUnavailableError(
            f"The model file in {directory} does not match its metadata (an interrupted "
            f"save or a damaged file). {_TRAIN_HINT}"
        )


def load_model(directory: Path) -> LoadedModel:
    metadata = _read_metadata(directory)
    _check_compatible(directory, metadata)
    try:
        pipeline = joblib.load(directory / MODEL_FILENAME)
    except Exception as error:
        raise ModelUnavailableError(
            f"The model file in {directory} could not be read. {_TRAIN_HINT}"
        ) from error
    if not isinstance(pipeline, Pipeline) or list(
        getattr(pipeline, "feature_names_in_", [])
    ) != list(FEATURE_COLUMNS):
        raise ModelUnavailableError(
            f"The file in {directory} is not a trained pipeline for these features. {_TRAIN_HINT}"
        )
    return LoadedModel(pipeline=pipeline, metadata=metadata)
