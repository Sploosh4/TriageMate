import os
import logging
import json
from datetime import datetime, timezone


_EXTRA_FIELDS = {
    "event",
    "duration_ms",
    "provider",
    "model",
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "estimated_cost_usd",
    "total_cost_usd",
}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _EXTRA_FIELDS:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, default=str)


LOG_FORMAT = os.getenv("TRIAGEMATE_LOG_FORMAT", "json")


def setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    if LOG_FORMAT == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.handlers = [handler]
    return root
