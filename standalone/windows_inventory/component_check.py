"""Independent, offline component checks over explicitly bound native evidence.

Rules are reviewed source interpretations, not facts created by this evaluator.
No network, shell, repair, Defender inference or persistence occurs here. Empty
rules preserve unknowns. Version intervals are closed and branch-specific: a
larger version outside the evidenced interval never becomes implicitly fixed.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import re
from urllib.parse import urlsplit

from standalone.evidence_pipeline.contracts import utc
from standalone.evidence_pipeline.assessment.windows_version_match import windows_build

from .contract import DeviceBinding, validate


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("Nonempty bounded text required")


@dataclass(frozen=True)
class SourceAnchor:
    """Exact retained source plus locator; a hash does not certify interpretation."""

    sha256: str
    url: str
    locator: str

    def __post_init__(self):
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.sha256
        ):
            raise ValueError("Source SHA-256 required")
        _text(self.url)
        parsed = urlsplit(self.url)
        local = self.url == "urn:sha256:" + self.sha256
        if not local and (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("HTTPS or content-addressed local provenance required")
        _text(self.locator)


@dataclass(frozen=True)
class ComponentIdentity:
    name: str
    family_name: str
    publisher: str
    architecture: str

    def __post_init__(self):
        for value in (self.name, self.family_name, self.publisher):
            _text(value)
        if self.architecture not in ("X64", "X86", "Arm64", "Neutral"):
            raise ValueError("Explicit native package architecture required")


@dataclass(frozen=True)
class AssemblyIdentity:
    name: str
    architecture: str
    public_key_token: str
    language: str

    def __post_init__(self):
        for value in (
            self.name,
            self.architecture,
            self.public_key_token,
            self.language,
        ):
            _text(value)


@dataclass(frozen=True)
class AssemblyObservation:
    native_id: str
    identity: AssemblyIdentity
    version: str
    observed_at: datetime
    active_manifest_link: bool
    source: SourceAnchor

    def __post_init__(self):
        _text(self.native_id)
        if (
            not isinstance(self.identity, AssemblyIdentity)
            or windows_build(self.version) is None
        ):
            raise ValueError("Decoded assembly identity and version required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        if type(self.active_manifest_link) is not bool or not isinstance(
            self.source, SourceAnchor
        ):
            raise ValueError("Explicit active-manifest linkage and proof required")


@dataclass(frozen=True)
class ComponentRule:
    rule_id: str
    component: ComponentIdentity
    cve: str
    update: str
    release: str
    os_branch: int
    os_architecture: str
    first_affected: str
    first_fixed: str
    last_verified: str
    identity_source: SourceAnchor
    vulnerability_source: SourceAnchor
    fix_source: SourceAnchor
    conditions_source: SourceAnchor
    conditions_complete: bool
    required_conditions: tuple[tuple[str, str], ...] = ()
    assembly: AssemblyIdentity | None = None

    def __post_init__(self):
        _text(self.rule_id)
        _text(self.update)
        if not isinstance(self.component, ComponentIdentity):
            raise ValueError("Exact package identity required")
        if self.assembly is not None and not isinstance(
            self.assembly, AssemblyIdentity
        ):
            raise ValueError("Explicit assembly version namespace required")
        if not isinstance(self.cve, str) or not re.fullmatch(
            r"CVE-[0-9]{4}-[0-9]{4,}", self.cve
        ):
            raise ValueError("Explicit CVE required")
        if not isinstance(self.release, str) or not re.fullmatch(
            r"[0-9]{2}H[12]", self.release
        ):
            raise ValueError("Explicit Windows release required")
        if type(self.os_branch) is not int or not 0 < self.os_branch < 1_000_000_000:
            raise ValueError("Explicit OS branch required")
        if self.os_architecture not in ("x64", "x86", "arm64"):
            raise ValueError("Explicit OS architecture required")
        versions = tuple(
            windows_build(v)
            for v in (self.first_affected, self.first_fixed, self.last_verified)
        )
        if any(v is None for v in versions):
            raise ValueError("Four-part numeric package versions required")
        if not versions[0] < versions[1] <= versions[2]:
            raise ValueError("Ordered affected/fixed/verified interval required")
        if len({v[:3] for v in versions}) != 1:
            raise ValueError("One explicit package version branch per rule required")
        for source in (
            self.identity_source,
            self.vulnerability_source,
            self.fix_source,
            self.conditions_source,
        ):
            if not isinstance(source, SourceAnchor):
                raise ValueError(
                    "Each applicability relationship requires source provenance"
                )
            if not source.url.startswith("https://"):
                raise ValueError("Rules require public source provenance")
        if type(self.conditions_complete) is not bool or not isinstance(
            self.required_conditions, tuple
        ):
            raise ValueError(
                "Explicit condition completeness and immutable conditions required"
            )
        keys = set()
        for pair in self.required_conditions:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("Condition key/value required")
            key, value = pair
            _text(key)
            _text(value)
            if key in keys:
                raise ValueError("Duplicate condition")
            keys.add(key)


@dataclass(frozen=True)
class CheckContext:
    """OS/condition facts collected with, and bound to, this inventory snapshot."""

    binding: DeviceBinding
    origin: str
    inventory_sha256: str
    observed_at: datetime
    operating_system: str
    release: str
    os_branch: int
    os_architecture: str
    source: SourceAnchor
    conditions: tuple[tuple[str, str], ...] = ()
    assemblies: tuple[AssemblyObservation, ...] = ()

    def __post_init__(self):
        if not isinstance(self.binding, DeviceBinding) or self.origin not in (
            "lab",
            "synthetic",
        ):
            raise ValueError("Dedicated-lab or synthetic device binding required")
        if not isinstance(self.inventory_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.inventory_sha256
        ):
            raise ValueError("Exact inventory hash required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        if not isinstance(self.source, SourceAnchor):
            raise ValueError("Retained context proof required")
        if not isinstance(self.assemblies, tuple) or any(
            not isinstance(a, AssemblyObservation) for a in self.assemblies
        ):
            raise ValueError("Immutable assembly observations required")
        if not isinstance(self.conditions, tuple):
            raise ValueError("Immutable conditions required")
        keys = set()
        for pair in self.conditions:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("Condition key/value required")
            key, value = pair
            _text(key)
            _text(value)
            if key in keys:
                raise ValueError("Duplicate condition")
            keys.add(key)


def check_inventory(raw, *, binding, context, rules, retained_sources):
    """Evaluate exact Appx or linked assembly rules in separate version namespaces.

    ``retained_sources`` maps SHA-256 to source bytes already collected under the
    evidence workflow. Callers own source review and locator interpretation. Rules
    must express every applicability condition; incomplete rules remain unknown.
    Supersedence must be resolved in source-backed rules, not inferred from KB order.
    """
    inventory = validate(raw, binding)
    return _check_validated(raw, inventory, binding, context, rules, retained_sources)


def _check_validated(raw, inventory, binding, context, rules, retained_sources):
    fingerprint = hashlib.sha256(raw).hexdigest()
    rules, anchors = _validate_check(
        fingerprint, inventory, binding, context, rules, retained_sources
    )
    rows = [_check_record(record, context, rules) for record in inventory["records"]]
    return dict(
        contract="triagemate-component-check-v1",
        origin=context.origin,
        inventory_sha256=fingerprint,
        observed_at=context.observed_at.isoformat(),
        defender_coverage="unverified",
        rules=[asdict(rule) for rule in rules],
        rows=rows,
        sources=[
            dict(sha256=a.sha256, url=a.url, locator=a.locator)
            for a in dict.fromkeys(anchors)
        ],
        limitations=[
            "Only supplied, reviewed source rules are evaluated; rule coverage is not exhaustive.",
            "Results concern the pinned historical snapshot, not current device state.",
            "Package, assembly, file and Windows OS versions are different namespaces.",
            "No Defender coverage, absence of other vulnerabilities, remediation event or patch execution is inferred.",
        ],
    )


def _validate_check(fingerprint, inventory, binding, context, rules, retained_sources):
    if (
        not isinstance(context, CheckContext)
        or context.binding != binding
        or context.inventory_sha256 != fingerprint
    ):
        raise ValueError("Context differs from inventory device or snapshot")
    started, finished = (
        utc(datetime.fromisoformat(inventory[k])) for k in ("started_at", "finished_at")
    )
    if not started <= context.observed_at <= finished:
        raise ValueError("Context time is outside the inventory observation window")
    rules = tuple(rules)
    if any(not isinstance(rule, ComponentRule) for rule in rules):
        raise ValueError("Validated component rules required")
    if len({rule.rule_id for rule in rules}) != len(rules):
        raise ValueError("Duplicate rule identity")
    anchors = [context.source]
    appx_ids = {r["native_id"] for r in inventory["records"] if r["kind"] == "appx"}
    for assembly in context.assemblies:
        if (
            assembly.native_id not in appx_ids
            or not started <= assembly.observed_at <= finished
        ):
            raise ValueError("Assembly is outside the pinned inventory identity/time")
        anchors.append(assembly.source)
    for rule in rules:
        anchors.extend(
            (
                rule.identity_source,
                rule.vulnerability_source,
                rule.fix_source,
                rule.conditions_source,
            )
        )
    for anchor in anchors:
        source = retained_sources.get(anchor.sha256)
        if (
            not isinstance(source, bytes)
            or hashlib.sha256(source).hexdigest() != anchor.sha256
        ):
            raise ValueError("Missing or altered retained evidence")
    return rules, anchors


def _check_record(record, context, rules):
    """Evaluate one already validated observation without materializing inventory."""
    row = dict(
        kind=record["kind"],
        native_id=record["native_id"],
        version=record["version"],
        state="unknown",
        reason="no_exact_source_rule",
        evaluations=[],
    )
    if record["kind"] != "appx":
        row["reason"] = "outside_appx_component_contract"
        return row
    selected = [
        rule
        for rule in rules
        if all(
            record.get(key) == getattr(rule.component, key)
            for key in ("name", "family_name", "publisher", "architecture")
        )
    ]
    for rule in selected:
        state, reason = _evaluate(record, context, rule)
        row["evaluations"].append(
            dict(
                rule_id=rule.rule_id,
                cve=rule.cve,
                update=rule.update,
                state=state,
                reason=reason,
                version_namespace="assembly" if rule.assembly else "appx_package",
            )
        )
    if selected:
        # No all-component/all-vulnerability conclusion from individual rules.
        row["reason"] = "per_cve_results_only"
        by_cve = {}
        for evaluation in row["evaluations"]:
            by_cve.setdefault(evaluation["cve"], []).append(evaluation)
        for evaluations in by_cve.values():
            states = {e["state"] for e in evaluations}
            if "fix_present" in states and "update_required" in states:
                for evaluation in evaluations:
                    evaluation.update(
                        state="unknown", reason="conflicting_source_rules"
                    )
    return row


def check_selected_components(raw, *, binding, origin, rules, retained_sources):
    """Evaluate the selected-component contract using its own native OS evidence.

    No full-inventory coverage is synthesized. Conditions other than native OS
    facts remain absent, and conflicting active identities remain unavailable.
    """
    from .component_snapshot import validate_selected

    snapshot = validate_selected(raw, binding)
    digest = hashlib.sha256(raw).hexdigest()
    source = SourceAnchor(
        digest, "urn:sha256:" + digest, "selected native OS and component observations"
    )
    assemblies = []
    for entry in snapshot["assemblies"]:
        identity = entry["identity"]
        assemblies.append(
            AssemblyObservation(
                entry["native_id"],
                AssemblyIdentity(
                    identity["name"],
                    identity["processorArchitecture"],
                    identity["publicKeyToken"],
                    identity["language"],
                ),
                identity["version"],
                entry["observed_at"],
                entry["active_manifest_link"],
                SourceAnchor(
                    entry["sha256"],
                    "urn:sha256:" + entry["sha256"],
                    "decoded active-link servicing manifest",
                ),
            )
        )
    os = snapshot["os"]
    # Only exact, collected Windows 11 captions enter the accepted scope.
    operating_system = (
        "Windows11"
        if os["caption"]
        in (
            "Microsoft Windows 11 Education",
            "Microsoft Windows 11 Enterprise",
            "Microsoft Windows 11 Pro",
            "Microsoft Windows 11 Home",
        )
        else "unverified"
    )
    context = CheckContext(
        binding,
        origin,
        digest,
        utc(datetime.fromisoformat(snapshot["finished_at"])),
        operating_system,
        os["release"],
        int(os["build"]),
        {"AMD64": "x64", "ARM64": "arm64", "x86": "x86"}.get(
            os["architecture"], "unverified"
        ),
        source,
        assemblies=tuple(assemblies),
    )
    retained = dict(retained_sources)
    retained.update(snapshot["sources"])
    retained[digest] = raw
    result = _check_validated(raw, snapshot, binding, context, rules, retained)
    result["input_contract"] = "triagemate-windows-component-observations-v1"
    result["not_observed"] = snapshot["not_observed"]
    result["collection_scope"] = snapshot["scope"]
    result["compressed_source_bytes_complete"] = all(
        a["compressed_bytes_retained"] for a in snapshot["assemblies"]
    )
    result["limitations"].append(
        "Decoded bytes are hash-verified; compressed decoding and hardlink ownership remain collector evidence. Missing compressed bytes cannot be independently decoded again."
    )
    return result


def _evaluate(record, context, rule):
    if context.operating_system != "Windows11":
        return "unknown", "outside_accepted_windows_11_scope"
    if (context.release, context.os_branch, context.os_architecture) != (
        rule.release,
        rule.os_branch,
        rule.os_architecture,
    ):
        return "unknown", "different_or_missing_os_target"
    if record.get("is_bundle") is True or record.get("is_resource_package") is True:
        return "unknown", "bundle_or_resource_requires_separate_rule_contract"
    if not any(s["install_state"] == "Installed" for s in record["user_states"]):
        return "unknown", "no_installed_user_evidence"
    if record.get("status") != "Ok":
        return "unknown", "installation_state_not_ok"
    if record.get("manifest", {}).get("state") != "read":
        return "unknown", "active_package_manifest_unverified"
    if record.get("manifest", {}).get("architecture_verified") is False:
        return "unknown", "active_manifest_architecture_unverified"
    if not rule.conditions_complete:
        return "unknown", "source_conditions_incomplete"
    conditions = dict(context.conditions)
    if any(conditions.get(k) != v for k, v in rule.required_conditions):
        return "unknown", "required_condition_missing_or_different"
    installed = windows_build(record["version"])
    if rule.assembly is not None:
        versions = {
            a.version
            for a in context.assemblies
            if a.native_id == record["native_id"]
            and a.identity == rule.assembly
            and a.active_manifest_link
        }
        if len(versions) != 1:
            return "unknown", "missing_or_conflicting_active_assembly"
        installed = windows_build(next(iter(versions)))
    first, fixed, last = (
        windows_build(v)
        for v in (rule.first_affected, rule.first_fixed, rule.last_verified)
    )
    if installed is None or not first <= installed <= last:
        return "unknown", "outside_evidenced_package_version_interval"
    if installed < fixed:
        return "update_required", "source_rule_affected_package_version"
    return "fix_present", "source_rule_fixed_package_version"
