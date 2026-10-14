"""Bounded line-index parsing shared by publisher-specific CSAF routes."""


def parse_paths(payload, resolve, *, max_records):
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("CSAF index must be nonempty immutable bytes")
    try:
        lines = payload.decode("utf-8-sig").splitlines()
    except UnicodeError as exc:
        raise ValueError("Invalid CSAF index encoding") from exc
    if len(lines) > max_records:
        raise ValueError("CSAF advisory index exceeds record limit")
    records, seen = [], set()
    for path in lines:
        record = resolve(path)
        if record.advisory_id in seen:
            raise ValueError("Repeated CSAF advisory identity")
        seen.add(record.advisory_id)
        records.append(record)
    return tuple(records)
