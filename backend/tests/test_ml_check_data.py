import hashlib
from pathlib import Path

import pytest

from app.ml.check_data import check_split, main
from app.ml.schema import DATASET_DIRNAME, SplitFile

CONTENT = b"id,label\n1,0\n2,1\n"


def _write_split(data_dir: Path, sha256: str | None = None) -> SplitFile:
    folder = data_dir / DATASET_DIRNAME
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "flows.csv").write_bytes(CONTENT)
    digest = hashlib.sha256(CONTENT).hexdigest() if sha256 is None else sha256
    return SplitFile(filename="flows.csv", rows=2, sha256=digest)


def test_missing_file_is_reported(tmp_path: Path) -> None:
    result = check_split(tmp_path, SplitFile(filename="absent.csv", rows=1, sha256=""))

    assert result.status == "missing"


def test_matching_file_is_ok(tmp_path: Path) -> None:
    split = _write_split(tmp_path)

    result = check_split(tmp_path, split)

    assert result.status == "ok"
    assert result.rows == 2


def test_file_with_a_different_checksum_is_flagged(tmp_path: Path) -> None:
    split = _write_split(tmp_path, sha256="0" * 64)

    assert check_split(tmp_path, split).status == "changed"


def test_main_succeeds_when_every_split_is_ok(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    split = _write_split(tmp_path)

    exit_code = main(tmp_path, splits=(split,))

    assert exit_code == 0
    assert "flows.csv" in capsys.readouterr().out


def test_main_fails_when_a_split_differs_from_the_verified_copy(tmp_path: Path) -> None:
    split = _write_split(tmp_path, sha256="0" * 64)

    assert main(tmp_path, splits=(split,)) == 1


def test_main_fails_and_points_to_the_readme_when_a_split_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(tmp_path, splits=(SplitFile(filename="absent.csv", rows=1, sha256=""),))

    assert exit_code == 1
    assert "README" in capsys.readouterr().out
