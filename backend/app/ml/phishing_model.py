"""Phishing text classifier: TF-IDF features with logistic regression.

The model is linear, so each prediction can be explained exactly: a word's
contribution is its weight times its TF-IDF value in that message.
"""

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import joblib
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.ml.persistence import (
    METADATA_FILENAME,
    MODEL_FILENAME,
    ModelMetadata,
    ModelUnavailableError,
    _file_sha256,
    _replace_atomically,
)

DECISION_THRESHOLD = 0.5
PHISHING_MODEL_NAME = "TF-IDF + logistic regression"
TEXT_FEATURE = "text"
MAX_MODEL_CHARS = 20_000
_TRAIN_HINT = (
    "Train one with `python -m app.ml.phishing_train` (see 'Phishing corpus' in the README)."
)
_NOT_FOUND_MESSAGE = (
    "No trained phishing model is available. Train one with `python -m app.ml.phishing_train`."
)
_UNUSABLE_MESSAGE = (
    "The stored phishing model cannot be used. Retrain it with `python -m app.ml.phishing_train`."
)


# The two corpora come from different years and sources, so dates and the legitimate set's
# mailing-list boilerplate would let the model separate them without reading any phishing cues.
_CORPUS_ARTIFACT_TERMS = frozenset(
    "january february march april may june july august september october november december "
    "jan feb mar apr jun jul aug sep sept oct nov dec mon tue wed thu fri sat sun "
    "mailman listinfo url wrote spamassassin xent fork razor sourceforge".split()
)


@dataclass(frozen=True)
class TermContribution:
    term: str
    weight: float  # positive pushes towards phishing, negative towards legitimate


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    # Letters only: numbers, and so years and dates, are not features.
                    token_pattern=r"(?u)\b[^\W\d_]{2,}\b",  # noqa: S106 - a regex
                    stop_words=sorted(_CORPUS_ARTIFACT_TERMS),
                    ngram_range=(1, 2),
                    min_df=3,
                    max_features=30_000,
                    sublinear_tf=True,
                ),
            ),
            ("model", LogisticRegression(C=4.0, class_weight="balanced", max_iter=1000)),
        ]
    )


def phishing_probability(pipeline: Pipeline, text: str) -> float:
    return float(pipeline.predict_proba([text[:MAX_MODEL_CHARS]])[0, 1])


def top_contributions(
    pipeline: Pipeline, text: str, limit: int = 5
) -> tuple[list[TermContribution], list[TermContribution]]:
    """Terms in this message pushing hardest towards phishing, and towards legitimate."""
    vectorizer: TfidfVectorizer = pipeline.named_steps["tfidf"]
    weights = pipeline.named_steps["model"].coef_[0]
    row = vectorizer.transform([text[:MAX_MODEL_CHARS]])
    names = vectorizer.get_feature_names_out()
    contributions = row.multiply(weights).tocoo()
    scored = sorted(zip(contributions.col, contributions.data, strict=True), key=lambda t: t[1])
    toward_legit = [TermContribution(str(names[i]), float(v)) for i, v in scored if v < 0]
    toward_phish = [TermContribution(str(names[i]), float(v)) for i, v in reversed(scored) if v > 0]
    return toward_phish[:limit], toward_legit[:limit]


def save_phishing_model(directory: Path, pipeline: Pipeline, metadata: ModelMetadata) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    model_path = directory / MODEL_FILENAME
    _replace_atomically(model_path, lambda path: joblib.dump(pipeline, path, compress=3))
    stored = replace(metadata, model_sha256=_file_sha256(model_path))
    _replace_atomically(
        directory / METADATA_FILENAME,
        lambda path: path.write_text(json.dumps(asdict(stored), indent=2), encoding="utf-8"),
    )


@dataclass(frozen=True)
class LoadedPhishingModel:
    pipeline: Pipeline
    metadata: ModelMetadata


def load_phishing_model(directory: Path) -> LoadedPhishingModel:
    """Loads a model this project saved; like the network model, only trust your own files."""
    metadata_path = directory / METADATA_FILENAME
    model_path = directory / MODEL_FILENAME
    if not metadata_path.is_file() or not model_path.is_file():
        raise ModelUnavailableError(
            f"No phishing model in {directory}. {_TRAIN_HINT}", _NOT_FOUND_MESSAGE
        )
    try:
        metadata = ModelMetadata(**json.loads(metadata_path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as error:
        raise ModelUnavailableError(
            f"Unreadable phishing model metadata in {directory}. {_TRAIN_HINT}", _UNUSABLE_MESSAGE
        ) from error
    problem = _compatibility_problem(model_path, metadata)
    if problem:
        raise ModelUnavailableError(f"{problem} {_TRAIN_HINT}", _UNUSABLE_MESSAGE)
    try:
        pipeline = joblib.load(model_path)
    except Exception as error:
        raise ModelUnavailableError(
            f"The phishing model in {directory} could not be read. {_TRAIN_HINT}", _UNUSABLE_MESSAGE
        ) from error
    if not isinstance(pipeline, Pipeline) or not hasattr(
        pipeline.named_steps.get("model"), "coef_"
    ):
        raise ModelUnavailableError(
            f"The file in {directory} is not a trained phishing pipeline. {_TRAIN_HINT}",
            _UNUSABLE_MESSAGE,
        )
    return LoadedPhishingModel(pipeline=pipeline, metadata=metadata)


def _compatibility_problem(model_path: Path, metadata: ModelMetadata) -> str:
    if metadata.sklearn_version != sklearn.__version__:
        return (
            f"The phishing model was built with scikit-learn {metadata.sklearn_version} "
            f"but {sklearn.__version__} is installed."
        )
    if metadata.feature_columns != [TEXT_FEATURE]:
        return "The phishing model expects a different input layout."
    if _file_sha256(model_path) != metadata.model_sha256:
        return "The phishing model file does not match its metadata."
    return ""
