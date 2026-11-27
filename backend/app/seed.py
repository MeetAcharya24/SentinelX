"""Loads the synthetic demo data into the alert database: `python -m app.seed`.

Used by the deployed demo so a fresh instance opens with something to look at. It reads
only what the repository already ships and labels every alert it stores as demo data:

- `samples/demo_security_log.csv`, a hand-written log (documentation-range addresses);
- 60 synthetic flows from `app.ml.demo_flows` (seeded, no dataset row copied);
- the matching synthetic blocklists in `samples/demo_blocklists/`, applied here
  regardless of `BLOCKLIST_DIR`;
- one synthetic threat-intelligence cache entry (source `demo_seed`, labelled as demo-only)
  for an address in the sample log, so `threat_intel_match` evidence always shows.

Nothing is read from `data/`, the network or the environment beyond the database path and
model folders. Running it twice stores nothing new: alerts are de-duplicated by content.
"""

import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime

import pandas as pd

from app.core.config import REPO_ROOT, Settings, get_settings
from app.detection.pipeline import alerts_from_flows, alerts_from_log
from app.detection.watchlist import load_watchlist
from app.ingestion.logs import LogFormat, parse_log
from app.intel.feeds import DEMO_SOURCE
from app.intel.lookup import ThreatIntel
from app.intel.store import IntelStore, Ioc
from app.ml.anomaly import ANOMALY_DIRNAME
from app.ml.demo_flows import generate_demo_flows
from app.ml.persistence import ModelUnavailableError, load_model
from app.ml.schema import FEATURE_COLUMNS
from app.storage.alerts import AlertStore

logger = logging.getLogger("sentinelx.seed")

SAMPLES_DIR = REPO_ROOT / "samples"
DEMO_LOG = SAMPLES_DIR / "demo_security_log.csv"
DEMO_BLOCKLISTS = SAMPLES_DIR / "demo_blocklists"
DEMO_FLOW_COUNT = 60
DEMO_FLOW_SEED = 7
# A documentation-range address (RFC 5737) that appears in the sample log, so no real
# host is ever named as malicious.
DEMO_INTEL_ADDRESS = "198.51.100.23"
DEMO_INTEL_NOTE = "demo-only: synthetic entry, not real intelligence"
DEMO_INTEL_CONFIDENCE = 50


def seed_demo_intel(store: IntelStore, *, now: datetime | None = None) -> None:
    """Caches the one synthetic indicator; its source name and label say it is not a real feed."""
    moment = now or datetime.now(UTC)
    indicator = Ioc(
        "ip",
        DEMO_INTEL_ADDRESS,
        first_seen=moment,
        malware=DEMO_INTEL_NOTE,
        confidence=DEMO_INTEL_CONFIDENCE,
    )
    store.replace_feed(DEMO_SOURCE, [indicator], now=moment)


def seed(settings: Settings) -> tuple[int, int]:
    """Stores the demo alerts and returns (log alerts, flow alerts) now on file for them."""
    store = AlertStore(settings.sqlite_path)
    intel_store = IntelStore(settings.sqlite_path)
    seed_demo_intel(intel_store)
    intel = ThreatIntel(intel_store)

    parsed = parse_log(DEMO_LOG.read_bytes(), LogFormat.CSV)
    watchlist = load_watchlist(DEMO_BLOCKLISTS)
    log_outcome = store.ingest(alerts_from_log(parsed, watchlist, intel), demo=True)

    forest = load_model(settings.model_dir).pipeline
    forest.set_params(model__n_jobs=1)
    anomaly = load_model(settings.model_dir / ANOMALY_DIRNAME).pipeline
    flows = generate_demo_flows(DEMO_FLOW_COUNT, DEMO_FLOW_SEED)
    features = pd.DataFrame([flow.features for flow in flows])[list(FEATURE_COLUMNS)]
    flow_outcome = store.ingest(alerts_from_flows(features, forest, anomaly), demo=True)
    return len(log_outcome.alerts), len(flow_outcome.alerts)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        from_log, from_flows = seed(get_settings())
    except (ModelUnavailableError, OSError, ValueError) as error:
        logger.error("Demo seeding failed: %s", error)
        return 1
    logger.info("Demo data on file: %d log alerts, %d network alerts.", from_log, from_flows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
