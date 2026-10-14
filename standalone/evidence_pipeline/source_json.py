"""Encode strict retained source JSON without converting Decimal through float."""

from decimal import Decimal
from io import StringIO
import json

# JSONEncoder.encode keeps its per-call state local. Reuse the strict encoder
# instead of constructing one for every key and scalar in a publisher record.
_scalar_encoder = json.JSONEncoder(
    ensure_ascii=False, allow_nan=False, separators=(",", ":")
)


def encode_source_records(value):
    return encode_source_text(value).encode()


def encode_source_text(value, *, sort_keys=False):
    """Write one result without constructing serialized copies at every level."""
    output = StringIO()

    def encode(item, ordered=sort_keys):
        if isinstance(item, Decimal):
            if not item.is_finite():
                raise ValueError("Nonfinite source number")
            output.write(str(item))
        elif isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("Source object keys must be strings")
            output.write("{")
            for index, key in enumerate(sorted(item) if ordered else item):
                if index:
                    output.write(",")
                output.write(_scalar_encoder.encode(key))
                output.write(":")
                encode(item[key], ordered)
            output.write("}")
        elif isinstance(item, (list, tuple)):
            output.write("[")
            for index, entry in enumerate(item):
                if index:
                    output.write(",")
                # Retain the historical source_json contract: sorting recurses
                # through JSON lists, while non-JSON tuples retain their order
                # and the insertion order of any dictionaries they contain.
                encode(entry, ordered and isinstance(item, list))
            output.write("]")
        else:
            output.write(_scalar_encoder.encode(item))

    try:
        encode(value)
        return output.getvalue()
    finally:
        output.close()
