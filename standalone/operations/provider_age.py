"""Provider clock observations, distinct from collection timing and record age."""

from datetime import datetime, time, timedelta, timezone

from standalone.evidence_pipeline.contracts import utc
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    EpssFeed,
    KevFeed,
    NvdFeed,
)
from standalone.evidence_pipeline.parsing.public_snapshot import PARSERS
from standalone.evidence_pipeline.parsing.csaf import CsafFeed
from standalone.evidence_pipeline.parsing.osv import OsvFeed
from standalone.evidence_pipeline.parsing.cve_program import CveProgramFeed
from standalone.evidence_pipeline.parsing.advisory_feeds import AdvisoryFeed


SUPPORTED = frozenset(PARSERS)

# Historical record age is distinct from the health of a verified collection.
COLLECTION_HEALTH_INPUTS = frozenset(
    {
        ("MSRC", "security_updates"),
        ("MSRC", "advisories"),
        ("CVE", "records"),
        ("CISA", "vulnrichment"),
        ("Microsoft Update Catalog", "updates"),
        ("WA SOC", "advisories"),
    }
)


def clock_basis(source, kind):
    return {
        ("FIRST", "epss"): "score_date",
        ("CISA", "kev"): "catalogue_release",
        ("NVD", "vulnerabilities"): "response_timestamp",
        ("MSRC", "security_updates"): "document_release",
        ("MSRC", "repository"): "oldest_document_release",
        ("MITRE ATT&CK", "enterprise_definitions"): "collection_modified",
    }.get((source, kind), "record_last_modified")


def record_clock(values, *, cve_times=False):
    """All records need a valid clock; a recent subset cannot hide unknown ages."""
    oldest = None
    for value in values:
        if not isinstance(value, str):
            return None, None, None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None and cve_times:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = utc(parsed)
            oldest = parsed if oldest is None else min(oldest, parsed)
        except ValueError:
            return None, None, None
    return (
        (oldest, "record_last_modified", "timestamp")
        if oldest is not None
        else (None, None, None)
    )


def provider_clock(feed):
    from standalone.evidence_pipeline.parsing.attack_definitions import AttackFeed
    from standalone.evidence_pipeline.parsing.cvrf_updates import CvrfUpdates
    from standalone.evidence_pipeline.parsing.cvrf_stream import (
        StreamedCvrfUpdates,
        document_metadata,
    )

    if (
        not isinstance(feed, PublicFeed)
        or (feed.scope.source, feed.scope.input_kind) not in SUPPORTED
    ):
        raise ValueError("Input has no supported provider contract")
    if isinstance(feed, EpssFeed):
        return (
            feed.score_timestamp
            or datetime.combine(feed.score_date, time.min, timezone.utc),
            "score_date",
            "timestamp" if feed.score_timestamp else "date",
        )
    if isinstance(feed, KevFeed):
        return feed.date_released, "catalogue_release", "timestamp"
    if isinstance(feed, NvdFeed):
        # This is response generation, not the last modification of every CVE.
        return feed.timestamp, "response_timestamp", "timestamp"
    if isinstance(feed, CsafFeed):
        return feed.updated_at, "record_last_modified", "timestamp"
    if isinstance(feed, (CvrfUpdates, StreamedCvrfUpdates)):
        tracking = document_metadata(feed.raw_payload).get("DocumentTracking")
        value = (
            tracking.get("CurrentReleaseDate") if isinstance(tracking, dict) else None
        )
        clock, _, precision = record_clock([value])
        return (
            (clock, "document_release", precision)
            if clock is not None
            else (None, None, None)
        )
    if isinstance(feed, AttackFeed):
        collections = feed.metadata.get("collections", [])
        # A collection clock describes the bundled release. Technique timestamps
        # do not substitute for a missing or ambiguous collection identity.
        if (
            not isinstance(collections, list)
            or len(collections) != 1
            or not isinstance(collections[0], dict)
        ):
            return None, None, None
        from standalone.evidence_pipeline.parsing.attack_definitions import stix_id

        try:
            stix_id(collections[0].get("id"), "x-mitre-collection")
        except (ValueError, AttributeError):
            return None, None, None
        clock, _, precision = record_clock([collections[0].get("modified")])
        return (
            (clock, "collection_modified", precision)
            if clock is not None
            else (None, None, None)
        )
    if isinstance(feed, OsvFeed):
        return record_clock(record.modified for record in feed.records)
    if isinstance(feed, CveProgramFeed):
        return record_clock(
            (record.metadata.get("dateUpdated") for record in feed.records),
            cve_times=True,
        )
    if (
        isinstance(feed, AdvisoryFeed)
        and feed.scope.source == "Microsoft Update Catalog"
    ):
        oldest = None
        for record in feed.records:
            notice = record.fields.get("notice")
            value = notice.get("updated_at") if isinstance(notice, dict) else None
            if not isinstance(value, str):
                return None, None, None
            try:
                parsed = datetime.strptime(value, "%m/%d/%Y").date()
                oldest = parsed if oldest is None else min(oldest, parsed)
            except ValueError:
                return None, None, None
        # Midnight is the comparison anchor for a calendar date, not an asserted
        # publisher timestamp. Keep date precision in notifications and evidence.
        return (
            (
                datetime.combine(oldest, time.min, timezone.utc),
                "record_last_modified",
                "date",
            )
            if oldest is not None
            else (None, None, None)
        )
    if isinstance(feed, AdvisoryFeed) and feed.scope.source == "Palo Alto Networks":
        return record_clock(
            (
                record.fields["document"]["cveMetadata"].get("dateUpdated")
                for record in feed.records
            ),
            cve_times=True,
        )
    if isinstance(feed, AdvisoryFeed) and feed.scope.source == "Cisco":
        return record_clock(
            record.fields["document"]["document"]["tracking"].get(
                "current_release_date"
            )
            for record in feed.records
        )
    # No collection timestamp or HTTP receipt time substitutes for a publisher clock.
    return None, None, None


def classify(provider_time, now, *, max_age_seconds, clock_skew_seconds=300):
    now = utc(now)
    if (
        type(max_age_seconds) is not int
        or not 1 <= max_age_seconds <= 366 * 86400
        or type(clock_skew_seconds) is not int
        or not 0 <= clock_skew_seconds <= 3600
    ):
        raise ValueError("Invalid provider-age threshold or clock allowance")
    if provider_time is None:
        return "unknown"
    provider_time = utc(provider_time)
    if provider_time > now + timedelta(seconds=clock_skew_seconds):
        return "future"
    return (
        "stale"
        if (now - provider_time).total_seconds() >= max_age_seconds
        else "healthy"
    )


def proof_storage_state(bundle):
    """Invalidate parsed observations when any replay input changes on disk.

    These metadata stamps are cache invalidators, not content verification.
    Replay still verifies the receipt and hashes before populating the cache.
    """
    stamps = []
    for path in (
        bundle,
        bundle / "receipt.json",
        bundle / "payload.bin",
        bundle / "wire.bin",
    ):
        try:
            info = path.lstat()
            stamps.append(
                (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
            )
        except FileNotFoundError:
            stamps.append(None)
    return tuple(stamps)


def read_clock(cursor, recipe, *, cache=None):
    """Read only the latest successful exact input and its saved wire evidence.

    No network, recollection or older-attempt fallback is permitted. Callers may
    cache a validated observation by attempt ID/fingerprint and unchanged proof
    storage; passage of time must still be classified on every monitoring tick.
    """
    if (recipe.scope.source, recipe.scope.input_kind) not in SUPPORTED:
        raise ValueError("Configured input has no supported provider clock")
    cursor.execute(
        "SELECT id::text,finished_at,input_fingerprint FROM evidence.collection_attempts "
        "WHERE connection_id=%s AND complete AND outcome='success' "
        "ORDER BY finished_at DESC,started_at DESC,id DESC LIMIT 1",
        (recipe.scope.connection_id,),
    )
    row = cursor.fetchone()
    result = dict(
        attempt_id=None,
        collected_at=None,
        provider_time=None,
        basis=None,
        precision=None,
    )
    collection_health = (
        recipe.scope.source,
        recipe.scope.input_kind,
    ) in COLLECTION_HEALTH_INPUTS
    if collection_health:
        result.update(health_time=None, health_basis="successful_collection")
    if row is None:
        return result
    run, finished, fingerprint = row
    cache_key = (recipe.scope, recipe.parameters, recipe.bundle_root)
    result.update(attempt_id=run, collected_at=finished.isoformat())
    try:
        storage = proof_storage_state(recipe.bundle_root / run)
    except OSError:
        if cache is not None:
            cache.pop(cache_key, None)
        return result
    identity = (run, finished, fingerprint, storage)
    if cache is not None and cache_key in cache and cache[cache_key][0] == identity:
        return dict(cache[cache_key][1])
    if cache is not None:
        cache.pop(cache_key, None)
    try:
        snapshot = prepare(
            recipe.scope,
            run,
            recipe.bundle_root / run,
            replay_only=True,
            **dict(recipe.parameters),
        )
        if (
            not snapshot.complete
            or snapshot.input_fingerprint != fingerprint
            or snapshot.finished_at != finished
        ):
            return result
        clock, basis, precision = provider_clock(snapshot.feed())
        if proof_storage_state(recipe.bundle_root / run) != storage:
            return result
        if collection_health:
            result["health_time"] = finished.isoformat()
        if clock is None:
            # A verified immutable payload with no publisher clock will not gain
            # one by reparsing it every minute. Failed/missing bundles below are
            # deliberately not cached, so repairing their storage is observable.
            if cache is not None:
                cache[cache_key] = (identity, dict(result))
            return result
        result.update(
            provider_time=utc(clock).isoformat(), basis=basis, precision=precision
        )
        if cache is not None:
            cache[cache_key] = (identity, dict(result))
    except (ValueError, OSError):
        # A missing or inconsistent bundle is not proof that the source is fresh.
        pass
    return result
