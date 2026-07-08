"""
Compute reference distributions for ML drift monitoring.

Reads backend/ml/training_data_v2.npz, extracts the 35 tabular features
(first 35 columns), computes per-feature min/max/equal-width bin boundaries
and expected proportions, and writes backend/ml/reference_distributions.json.

Idempotent — running it multiple times produces the same output.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.compute_reference_dists")

NUM_BINS = 10

ML_DIR = Path(__file__).parent.parent / "ml"
NPZ_PATH = ML_DIR / "training_data_v2.npz"
OUTPUT_PATH = ML_DIR / "reference_distributions.json"


def main():
    logger.info("Loading NPZ from %s", NPZ_PATH)
    data = np.load(NPZ_PATH, allow_pickle=True)

    X = data["X"]  # shape: (253568, 419)
    columns = data["columns"]  # 35 tabular column names
    num_samples = X.shape[0]

    logger.info("NPZ loaded: X=%s, %d tabular columns", X.shape, len(columns))

    # Extract only the 35 tabular features
    X_tab = X[:, :35]

    features = {}
    for i, col_name in enumerate(columns):
        col_values = X_tab[:, i]
        col_min = float(col_values.min())
        col_max = float(col_values.max())

        # Build 10 equal-width bin boundaries
        bin_width = (col_max - col_min) / NUM_BINS if col_max > col_min else 1.0
        bins = [col_min + j * bin_width for j in range(NUM_BINS + 1)]

        # Count samples per bin and compute expected proportions
        counts = np.zeros(NUM_BINS, dtype=np.int64)
        for val in col_values:
            idx = (
                min(int((val - col_min) / bin_width), NUM_BINS - 1)
                if bin_width > 0
                else 0
            )
            if idx < 0:
                idx = 0
            if idx >= NUM_BINS:
                idx = NUM_BINS - 1
            counts[idx] += 1

        expected = [float(c / num_samples) for c in counts]

        # Round values for cleaner JSON output
        bins_rounded = [round(b, 6) for b in bins]
        expected_rounded = [round(p, 6) for p in expected]

        features[str(col_name)] = {
            "min": col_min,
            "max": col_max,
            "bins": bins_rounded,
            "expected": expected_rounded,
        }

        logger.debug(
            "  %s: min=%s, max=%s, bins=[%s, ... %s]",
            col_name,
            col_min,
            col_max,
            bins_rounded[0],
            bins_rounded[-1],
        )

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "training_data_v2.npz",
        "num_samples": int(num_samples),
        "features": features,
    }

    logger.info("Writing reference distributions to %s", OUTPUT_PATH)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    logger.info(
        "Done — %d features written, %d samples",
        len(features),
        num_samples,
    )


if __name__ == "__main__":
    main()
