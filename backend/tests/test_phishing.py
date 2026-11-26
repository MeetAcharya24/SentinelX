"""Phishing email parsing, signals, model persistence and the classify endpoint."""

import mailbox
from collections.abc import Callable
from pathlib import Path

import pytest
import sklearn
from fastapi.testclient import TestClient
from sklearn.pipeline import Pipeline

from app.detection.phishing_signals import extract_signals
from app.ingestion.email import EmailParseError, parse_email
from app.main import create_app
from app.ml.persistence import ModelMetadata, ModelUnavailableError
from app.ml.phishing_data import PhishingCorpusError, load_corpus
from app.ml.phishing_model import (
    TEXT_FEATURE,
    build_pipeline,
    load_phishing_model,
    phishing_probability,
    save_phishing_model,
    top_contributions,
)

PHISHING_EMAIL = (
    b"From: Support <support@paypa1-secure.example>\r\n"
    b"Reply-To: collect@mailbox.example\r\n"
    b"Subject: Urgent: verify your account\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b'<p>Your account will be suspended. <a href="http://203.0.113.9/login">'
    b"https://www.paypal.com/login</a> to confirm your password immediately.</p>"
)
LEGIT_EMAIL = (
    b"From: Ana <ana@team.example>\r\nSubject: Lunch notes\r\n\r\n"
    b"Here are the notes from the planning meeting, see you on Thursday."
)


def _with_attachment(filename: str) -> bytes:
    return (
        b"From: a@b.example\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="x"\r\n\r\n'
        b"--x\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n"
        b"--x\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="' + filename.encode() + b'"\r\n\r\n'
        b"MZ\r\n--x--\r\n"
    )


def test_parse_reads_headers_links_and_visible_text() -> None:
    parsed = parse_email(PHISHING_EMAIL)

    assert parsed.from_address == "support@paypa1-secure.example"
    assert parsed.reply_to_address == "collect@mailbox.example"
    assert "will be suspended" in parsed.body_text
    assert "<a" not in parsed.body_text
    assert [(link.url, link.text) for link in parsed.links] == [
        ("http://203.0.113.9/login", "https://www.paypal.com/login")
    ]


def test_parse_treats_headerless_input_as_the_message_text() -> None:
    parsed = parse_email(b"Please verify your account at http://example.test/x now")

    assert "verify your account" in parsed.body_text
    assert [link.url for link in parsed.links] == ["http://example.test/x"]


@pytest.mark.parametrize("raw", [b"", b"   \n  "])
def test_parse_rejects_empty_input(raw: bytes) -> None:
    with pytest.raises(EmailParseError):
        parse_email(raw)


def test_parse_lists_attachment_names_without_reading_them() -> None:
    assert parse_email(_with_attachment("invoice.exe")).attachment_names == ("invoice.exe",)


def test_signals_name_each_observation_with_its_example() -> None:
    signals = {signal.code: signal for signal in extract_signals(parse_email(PHISHING_EMAIL))}

    assert set(signals) == {
        "reply_to_mismatch",
        "ip_address_link",
        "link_text_mismatch",
        "urgency_language",
        "credential_request",
    }
    assert signals["ip_address_link"].examples == ("203.0.113.9",)
    assert "paypal.com" in signals["link_text_mismatch"].examples[0]


def test_signals_are_empty_for_an_ordinary_message() -> None:
    assert extract_signals(parse_email(LEGIT_EMAIL)) == []


def test_risky_attachment_signal() -> None:
    signals = extract_signals(parse_email(_with_attachment("Scan.PDF.scr")))

    assert [signal.code for signal in signals] == ["risky_attachment"]


PHISH_TEXTS = [f"Urgent verify your account password bank paypal login {i}" for i in range(12)]
LEGIT_TEXTS = [f"Meeting notes agenda lunch project review thanks {i}" for i in range(12)]


@pytest.fixture(scope="module")
def trained_pipeline() -> Pipeline:
    texts = PHISH_TEXTS + LEGIT_TEXTS
    return build_pipeline().fit(texts, [1] * len(PHISH_TEXTS) + [0] * len(LEGIT_TEXTS))


def test_model_scores_and_explains_a_message(trained_pipeline: Pipeline) -> None:
    text = "Please verify your account password"

    toward_phishing, toward_legitimate = top_contributions(trained_pipeline, text, limit=10)

    assert phishing_probability(trained_pipeline, text) > 0.5
    assert {c.term for c in toward_phishing} >= {"verify", "account", "password"}
    assert all(c.weight > 0 for c in toward_phishing)
    assert all(c.weight < 0 for c in toward_legitimate)


def _metadata(**overrides: object) -> ModelMetadata:
    fields: dict[str, object] = {
        "model_name": "test model",
        "trained_at": "2026-01-01T00:00:00+00:00",
        "training_rows": 24,
        "feature_columns": [TEXT_FEATURE],
        "sklearn_version": sklearn.__version__,
        "test_metrics": {
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "accuracy": 1.0,
            "false_positive_rate": 0.0,
            "test_rows": 6,
            "test_attack_share": 0.5,
        },
    }
    return ModelMetadata(**{**fields, **overrides})  # type: ignore[arg-type]


def test_saved_model_round_trips(trained_pipeline: Pipeline, tmp_path: Path) -> None:
    save_phishing_model(tmp_path, trained_pipeline, _metadata())

    loaded = load_phishing_model(tmp_path)

    assert loaded.metadata.model_name == "test model"
    assert phishing_probability(loaded.pipeline, "verify your account") > 0.5


def test_missing_and_mismatched_models_are_unavailable(
    trained_pipeline: Pipeline, tmp_path: Path
) -> None:
    with pytest.raises(ModelUnavailableError):
        load_phishing_model(tmp_path / "absent")

    save_phishing_model(tmp_path, trained_pipeline, _metadata(feature_columns=["other"]))
    with pytest.raises(ModelUnavailableError):
        load_phishing_model(tmp_path)


def test_load_corpus_reads_both_classes_and_drops_duplicates(tmp_path: Path) -> None:
    root = tmp_path / "phishing"
    root.mkdir()
    box = mailbox.mbox(root / "phishing0.mbox")
    box.lock()
    for _ in range(2):  # the same campaign message sent twice
        box.add(PHISHING_EMAIL)
    box.flush()
    box.unlock()
    for name in ("phishing1.mbox", "phishing2.mbox"):
        (root / name).write_bytes(b"")
    for folder in ("easy_ham", "easy_ham_2", "hard_ham"):
        (root / "ham" / folder).mkdir(parents=True)
    (root / "ham" / "easy_ham" / "1.txt").write_bytes(LEGIT_EMAIL)

    corpus = load_corpus(tmp_path)

    assert corpus.labels == (1, 0)
    assert corpus.duplicates_removed == 1


def test_load_corpus_names_missing_files(tmp_path: Path) -> None:
    with pytest.raises(PhishingCorpusError, match="phishing0.mbox"):
        load_corpus(tmp_path)


@pytest.fixture
def phishing_client(
    make_settings: Callable[..., object], trained_pipeline: Pipeline, tmp_path: Path
) -> TestClient:
    save_phishing_model(tmp_path, trained_pipeline, _metadata())
    return TestClient(create_app(make_settings(phishing_model_dir=tmp_path)))  # type: ignore[arg-type]


def _classify(client: TestClient, body: bytes, content_type: str = "message/rfc822"):
    return client.post(
        "/api/v1/phishing/classify", content=body, headers={"content-type": content_type}
    )


def test_classify_returns_verdict_with_signals_and_terms(phishing_client: TestClient) -> None:
    response = _classify(phishing_client, PHISHING_EMAIL)

    data = response.json()["data"]
    assert response.status_code == 200
    assert data["label"] == "phishing"
    assert 0.5 <= data["confidence"] <= 1.0
    assert {s["code"] for s in data["signals"]} >= {"ip_address_link", "reply_to_mismatch"}
    assert data["model_terms"]["toward_phishing"]
    assert data["links_found"] == ["http://203.0.113.9/login"]
    assert data["model"]["test_metrics"]["test_rows"] == 6


def test_classify_legitimate_message_has_no_signals(phishing_client: TestClient) -> None:
    data = _classify(phishing_client, LEGIT_EMAIL, "text/plain").json()["data"]

    assert data["label"] == "legitimate"
    assert data["signals"] == []


def test_classify_rejects_other_content_types(phishing_client: TestClient) -> None:
    response = _classify(phishing_client, b"{}", "application/json")

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_email_type"


def test_classify_rejects_empty_email(phishing_client: TestClient) -> None:
    response = _classify(phishing_client, b"  ")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_email"


def test_classify_is_503_without_a_trained_model(
    make_settings: Callable[..., object], tmp_path: Path
) -> None:
    client = TestClient(create_app(make_settings(phishing_model_dir=tmp_path / "absent")))  # type: ignore[arg-type]

    response = _classify(client, LEGIT_EMAIL)

    assert response.status_code == 503
    assert "phishing_train" in response.json()["error"]["message"]


def test_train_cli_reports_metrics_and_saves_a_model(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.ml.phishing_train import main

    root = tmp_path / "data" / "phishing"
    root.mkdir(parents=True)
    box = mailbox.mbox(root / "phishing0.mbox")
    box.lock()
    for text in PHISH_TEXTS:
        box.add(f"Subject: {text}\n\n{text} {text}\n".encode())
    box.flush()
    box.unlock()
    for name in ("phishing1.mbox", "phishing2.mbox"):
        (root / name).write_bytes(b"")
    for folder in ("easy_ham", "easy_ham_2", "hard_ham"):
        (root / "ham" / folder).mkdir(parents=True)
    for index, text in enumerate(LEGIT_TEXTS):
        (root / "ham" / "easy_ham" / f"{index}.txt").write_bytes(
            f"Subject: {text}\n\n{text} {text}\n".encode()
        )

    exit_code = main(tmp_path / "data", tmp_path / "model")

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Confusion matrix" in output
    assert load_phishing_model(tmp_path / "model").metadata.training_rows == 19


def test_train_cli_names_a_missing_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.ml.phishing_train import main

    assert main(tmp_path) == 1
    assert "Missing corpus files" in capsys.readouterr().out
