"""Column layout of the UNSW-NB15 pre-split training and testing CSVs.

Taken from the published files themselves. They carry 42 flow features (a
reduced set of the 49 listed in the dataset's `NUSW-NB15_features.csv`, with
some columns renamed), plus a row id and the two target columns.
"""

from dataclasses import dataclass

DATASET_DIRNAME = "unsw-nb15"

# Rows are ordered by class in the published files, so the id tracks the label
# and must never be used as a feature.
ID_COLUMN = "id"
LABEL_COLUMN = "label"
ATTACK_CATEGORY_COLUMN = "attack_cat"
NORMAL_CATEGORY = "Normal"

CATEGORICAL_FEATURES: tuple[str, ...] = ("proto", "service", "state")

NUMERIC_FEATURES: tuple[str, ...] = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
)

FEATURE_COLUMNS: tuple[str, ...] = CATEGORICAL_FEATURES + NUMERIC_FEATURES
REQUIRED_COLUMNS: tuple[str, ...] = FEATURE_COLUMNS + (ATTACK_CATEGORY_COLUMN, LABEL_COLUMN)


@dataclass(frozen=True)
class SplitFile:
    """One published split, with the size and checksum of the verified copy."""

    filename: str
    rows: int
    sha256: str


TRAINING_SPLIT = SplitFile(
    filename="UNSW_NB15_training-set.csv",
    rows=175_341,
    sha256="bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
)
TESTING_SPLIT = SplitFile(
    filename="UNSW_NB15_testing-set.csv",
    rows=82_332,
    sha256="734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
)
