"""Pure offline synthetic EPSS contract. No network, database or legacy API changes."""

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
import hashlib
import json
import re

CONTRACT = "triagemate-synthetic-epss-v1"
SOURCE_SCOPE = "offline-synthetic-epss-v1"


class ValidationError(ValueError):
    """The entire payload must be rejected; messages never echo source content."""


@dataclass(frozen=True)
class Observation:
    cve_id: str
    probability: Decimal
    percentile: Decimal | None
    score_date: date
    model_version: str | None
    content_hash: str


@dataclass(frozen=True)
class Payload:
    fixture_id: str
    input_fingerprint: str
    observations: tuple[Observation, ...]
    origin: str = "synthetic"
    source_scope: str = SOURCE_SCOPE
    contract: str = CONTRACT


def fingerprint(raw: bytes) -> str:
    """Exact bytes, fixed scope and contract; also usable for invalid/empty input."""
    if not isinstance(raw, bytes):
        raise TypeError("Payload must be UTF-8 bytes")
    return hashlib.sha256(
        CONTRACT.encode() + b"\0" + SOURCE_SCOPE.encode() + b"\0" + raw
    ).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(_):
    raise ValidationError("Nonfinite JSON number")


def _decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|1)(?:\.[0-9]+)?", value):
        raise ValidationError("Scores must be decimal strings between zero and one")
    # PostgreSQL unconstrained numeric supports at most 16383 fractional digits.
    if len(value.partition(".")[2]) > 16383:
        raise ValidationError("Score exceeds PostgreSQL numeric scale")
    number = Decimal(value)
    if not number.is_finite() or not Decimal(0) <= number <= Decimal(1):
        raise ValidationError("Score outside zero to one")
    return number


def _canonical_decimal(value):
    if value is None:
        return None
    # Decimal.normalize() uses ambient precision and can silently round.
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def parse_payload(raw: bytes) -> Payload:
    digest = fingerprint(raw)
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_float=Decimal,
            parse_constant=_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValidationError("Invalid UTF-8 JSON or duplicate key") from error
    if not isinstance(data, dict) or set(data) != {"origin", "fixture_id", "data"}:
        raise ValidationError("Expected origin, fixture_id and data")
    if data["origin"] != "synthetic":
        raise ValidationError("Only explicitly synthetic input is accepted")
    fixture = data["fixture_id"]
    if not isinstance(fixture, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", fixture
    ):
        raise ValidationError("Invalid synthetic fixture attribution")
    if not isinstance(data["data"], list):
        raise ValidationError("Data must be a list")
    observations = []
    seen = set()
    for item in data["data"]:
        required = {"cve", "epss", "date"}
        if (
            not isinstance(item, dict)
            or not required <= set(item)
            or set(item) - (required | {"percentile", "model_version"})
        ):
            raise ValidationError("Invalid observation fields")
        cve = item["cve"]
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            raise ValidationError("Invalid canonical CVE identity")
        stamp = item["date"]
        if not isinstance(stamp, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}", stamp
        ):
            raise ValidationError("Invalid score date")
        try:
            score_date = date.fromisoformat(stamp)
        except ValueError as error:
            raise ValidationError("Invalid score date") from error
        key = (cve, score_date)
        if key in seen:
            raise ValidationError("Duplicate CVE/date observation")
        seen.add(key)
        probability = _decimal(item["epss"])
        percentile = (
            None if item.get("percentile") is None else _decimal(item["percentile"])
        )
        model = item.get("model_version")
        if model is not None and (
            not isinstance(model, str)
            or not model.strip()
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in model)
        ):
            raise ValidationError("Invalid model version")
        canonical = {
            "contract": CONTRACT,
            "scope": SOURCE_SCOPE,
            "origin": "synthetic",
            "fixture_id": fixture,
            "cve": cve,
            "date": stamp,
            "epss": _canonical_decimal(probability),
            "percentile": _canonical_decimal(percentile),
            "model_version": model,
        }
        content_hash = hashlib.sha256(
            json.dumps(
                canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        observations.append(
            Observation(cve, probability, percentile, score_date, model, content_hash)
        )
    return Payload(
        fixture,
        digest,
        tuple(sorted(observations, key=lambda r: (r.cve_id, r.score_date))),
    )
