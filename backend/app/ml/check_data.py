"""Checks that the UNSW-NB15 files are downloaded: `python -m app.ml.check_data`."""

import hashlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from app.core.config import get_settings
from app.ml.dataset import split_path
from app.ml.schema import TESTING_SPLIT, TRAINING_SPLIT, SplitFile

_CHUNK_BYTES = 1024 * 1024

_MESSAGES = {
    "ok": "matches the verified copy",
    "changed": "differs from the verified copy (the publisher may have updated it)",
    "missing": "not found",
}


@dataclass(frozen=True)
class SplitCheck:
    filename: str
    status: Literal["ok", "changed", "missing"]
    rows: int | None = None


def _digest_and_rows(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    newlines = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
            newlines += chunk.count(b"\n")
    return digest.hexdigest(), max(newlines - 1, 0)  # minus the header line


def check_split(data_dir: Path, split: SplitFile) -> SplitCheck:
    path = split_path(data_dir, split)
    if not path.is_file():
        return SplitCheck(filename=split.filename, status="missing")
    digest, rows = _digest_and_rows(path)
    status = "ok" if digest == split.sha256 else "changed"
    return SplitCheck(filename=split.filename, status=status, rows=rows)


def main(
    data_dir: Path | None = None,
    splits: Sequence[SplitFile] = (TRAINING_SPLIT, TESTING_SPLIT),
) -> int:
    data_dir = data_dir or get_settings().data_dir
    checks = [check_split(data_dir, split) for split in splits]
    for check in checks:
        rows = "" if check.rows is None else f" ({check.rows:,} rows)"
        print(f"{check.filename}: {_MESSAGES[check.status]}{rows}")
    if all(check.status == "ok" for check in checks):
        return 0
    print(f"Expected under {data_dir}. See 'Dataset' in the README for the download step.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
