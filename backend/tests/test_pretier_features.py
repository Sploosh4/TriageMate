"""
Tests for ml.pretier_features — shared feature extraction for the Pre-Tier
multi-label classifier.

Tests cover:
  - extract_features() returns correct dict keys for known hostname patterns
  - feature_vector_to_array() returns exactly 60 numeric values
  - get_feature_names() returns 60 unique, deterministic names
  - get_feature_count() returns 60
  - Edge cases: empty string, None, unrecognised patterns
  - Index 59 is system_category (ordinal 0-8)
  - Known hostnames like hr.corehealth.health.wa.gov.au
"""

import pytest


def _get_nonzero_tabular(features: dict) -> dict:
    """Return only nonzero feature entries from an extract_features() dict."""
    return {k: v for k, v in features.items() if v != 0}


class TestExtractFeatures:
    """Feature extraction logic for WA Government hostnames."""

    # ── Known agency patterns ─────────────────────────────────────────

    def test_health_dot_wa_gov_au(self):
        """health.wa.gov.au — no agency detected (health is the machine name)."""
        from ml.pretier_features import extract_features

        f = extract_features("health.wa.gov.au")
        assert f.get("env_code") == 0
        # 'health' lands as the machine-name part, not a subdomain agency
        assert f.get("agency_health") == 0
        assert isinstance(f.get("system_category"), int)

    def test_sso_justice_wa_gov_au(self):
        """sso.justice.wa.gov.au → agency_justice=1."""
        from ml.pretier_features import extract_features

        f = extract_features("sso.justice.wa.gov.au")
        assert f.get("agency_justice") == 1
        assert f.get("env_code") == 0  # 'sso' not a recognised env code

    def test_mail_doj_wa_gov_au(self):
        """mail.doj.wa.gov.au — 'doj' is not in AGENCIES or AGENCY_ALIASES,
        so no agency_* flag is set. role_mail=1 and system_category=2
        (productivity/collaboration) are expected."""
        from ml.pretier_features import extract_features

        f = extract_features("mail.doj.wa.gov.au")

        # No agency match (doj → communities mapping is not yet implemented)
        for key in [k for k in f if k.startswith("agency_")]:
            assert f[key] == 0, f"Expected no agency match, got {key}=1"

        # Role and system category
        assert f.get("role_mail") == 1
        # 'mail' → productivity/collaboration (category 2)
        assert f.get("system_category") == 2
        # Environment code default
        assert f.get("env_code") == 0

    def test_hr_corehealth_health_wa_gov_au(self):
        """hr.corehealth.health.wa.gov.au → agency_health=1,
        data_classification_code=2 (hr → Official), system_category=8."""
        from ml.pretier_features import extract_features

        f = extract_features("hr.corehealth.health.wa.gov.au")
        assert f.get("agency_health") == 1
        # 'hr' triggers CATEGORY_2_KEYWORDS → data_classification_code=2
        assert f.get("data_classification_code") == 2
        # 'corehealth' not in KNOWN_SYSTEM_NAMES and no match → category 8
        assert f.get("system_category") == 8

    # ── Edge cases ────────────────────────────────────────────────────

    def test_empty_string_hostname(self):
        """Empty string should not crash and returns valid feature dict."""
        from ml.pretier_features import extract_features

        f = extract_features("")
        assert isinstance(f, dict)
        assert f.get("env_code") == 0
        # All agency flags should be 0
        for k in f:
            if k.startswith("agency_"):
                assert f[k] == 0
        # Empty string has no system name match → fallback to category 8
        assert f.get("system_category") == 8

    def test_none_hostname_raises(self):
        """None hostname raises AttributeError (type hint says str but no guard)."""
        from ml.pretier_features import extract_features

        with pytest.raises(AttributeError):
            extract_features(None)  # type: ignore[arg-type]

    def test_unknown_hostname_no_patterns(self):
        """Hostname with no recognisable WA Gov patterns."""
        from ml.pretier_features import extract_features

        f = extract_features("unknown.hostname.local")
        assert f.get("env_code") == 0
        for k in f:
            if k.startswith("agency_"):
                assert f[k] == 0
        # No keyword match → system_category=8 (unknown system name)
        assert f.get("system_category") == 8

    # ── Environment encoding ──────────────────────────────────────────

    @pytest.mark.parametrize(
        "hostname, expected_env",
        [
            ("prd-server.health.wa.gov.au", 1),
            ("stg-server.health.wa.gov.au", 2),
            ("dev-server.health.wa.gov.au", 3),
            ("tst-server.health.wa.gov.au", 4),
            ("eol-server.health.wa.gov.au", 0),
            # per-PRD-* starts with 'per', not 'prd' → env_code=0
            ("per-PRD-WEB01.health.wa.gov.au", 0),
        ],
    )
    def test_env_code(self, hostname, expected_env):
        from ml.pretier_features import extract_features

        f = extract_features(hostname)
        assert f.get("env_code") == expected_env, (
            f"Expected env_code={expected_env} for {hostname}, got {f.get('env_code')}"
        )

    # ── System category ordinal ───────────────────────────────────────

    def test_system_category_index_59(self):
        """Verify system_category is at index 59 in the feature order."""
        from ml.pretier_features import get_feature_names

        names = get_feature_names()
        assert names[59] == "system_category", (
            f"Expected index 59 to be 'system_category', got '{names[59]}'"
        )

    @pytest.mark.parametrize(
        "hostname, expected_cat",
        [
            # Category 0: No system name
            ("", 8),  # empty → fallback to category 8
            # Category 1: Infrastructure
            ("per-PRD-BACKUP-SVR01.health.wa.gov.au", 1),
            ("per-PRD-DNS-SVR01.health.wa.gov.au", 1),
            ("per-PRD-PRINT-SVR01.health.wa.gov.au", 1),
            # Category 2: Productivity
            ("per-PRD-EXCHANGE-CAS01.health.wa.gov.au", 2),
            ("per-PRD-MAIL-SVR01.health.wa.gov.au", 2),
            ("per-PRD-CONFLUENCE01.health.wa.gov.au", 2),
            # Category 3: Enterprise/LOB
            ("per-PRD-SAP-FIN01.finance.wa.gov.au", 3),
            ("per-PRD-ORACLE-DB01.health.wa.gov.au", 3),
            ("per-PRD-MOVEIT-WEB01.health.wa.gov.au", 3),
            ("per-PRD-TEMIS-APP01.transport.wa.gov.au", 3),  # temis → cat 3
            # Category 4: Access/security
            ("per-PRD-CITRIX-ADC01.health.wa.gov.au", 4),
            ("per-PRD-VPN-GW01.health.wa.gov.au", 4),
            ("per-PRD-FIREWALL01.health.wa.gov.au", 4),
            # Category 7: Known system name (not matching 1-6)
            ("per-PRD-SHIELD01.police.wa.gov.au", 7),
            # Category 8: Unknown / fallback (no KNOWN_SYSTEM_NAMES match
            # and no category keyword match in the fallback path)
            ("per-PRD-WEB-APP01.health.wa.gov.au", 8),
            ("per-PRD-API-GW01.health.wa.gov.au", 8),
            ("per-PRD-PORTAL01.health.wa.gov.au", 8),
            ("per-PRD-DB-CLUSTER01.health.wa.gov.au", 8),
            ("per-PRD-SQL-SVR01.health.wa.gov.au", 8),
            ("per-PRD-FOO-BAR01.health.wa.gov.au", 8),
        ],
    )
    def test_system_category_values(self, hostname, expected_cat):
        from ml.pretier_features import extract_features

        f = extract_features(hostname)
        assert f.get("system_category") == expected_cat, (
            f"Expected system_category={expected_cat} for {hostname}, "
            f"got {f.get('system_category')}"
        )

    # ── Role keyword detection ────────────────────────────────────────

    @pytest.mark.parametrize(
        "hostname, expected_role",
        [
            ("per-PRD-WEB01.health.wa.gov.au", "role_web"),
            ("per-PRD-API-GW01.health.wa.gov.au", "role_api"),
            ("per-PRD-DB-CLUSTER01.health.wa.gov.au", "role_db"),
            ("per-PRD-DC-ACT01.health.wa.gov.au", "role_dc"),
            ("per-PRD-SPLUNK-IDX01.health.wa.gov.au", "role_log"),
            ("per-PRD-MAIL-SVR01.health.wa.gov.au", "role_mail"),
            ("per-PRD-SAP-FIN01.finance.wa.gov.au", "role_sap"),
            ("per-PRD-SERVICENOW01.health.wa.gov.au", "role_itsm"),
        ],
    )
    def test_role_keyword_detection(self, hostname, expected_role):
        from ml.pretier_features import extract_features

        f = extract_features(hostname)
        assert f.get(expected_role) == 1, f"Expected {expected_role}=1 for {hostname}"


class TestFeatureVectorToArray:
    """Conversion from feature dict to fixed-order array."""

    def test_returns_exactly_60_values(self):
        from ml.pretier_features import extract_features, feature_vector_to_array

        f = extract_features("per-PRD-WEB01.health.wa.gov.au")
        arr = feature_vector_to_array(f)
        assert len(arr) == 60, f"Expected 60 values, got {len(arr)}"

    def test_all_numeric(self):
        from ml.pretier_features import extract_features, feature_vector_to_array

        f = extract_features("per-PRD-SAP-FIN01.finance.wa.gov.au")
        arr = feature_vector_to_array(f)
        for i, v in enumerate(arr):
            assert isinstance(v, (int, float)), (
                f"Value at index {i} is {type(v).__name__}, expected int/float"
            )

    def test_order_is_fixed_and_deterministic(self):
        from ml.pretier_features import extract_features, feature_vector_to_array

        f1 = extract_features("per-PRD-WEB01.health.wa.gov.au")
        f2 = extract_features("per-PRD-WEB01.health.wa.gov.au")
        arr1 = feature_vector_to_array(f1)
        arr2 = feature_vector_to_array(f2)
        assert arr1 == arr2, "Same hostname should produce identical arrays"

    def test_different_hostnames_differ(self):
        from ml.pretier_features import extract_features, feature_vector_to_array

        a1 = feature_vector_to_array(extract_features("per-PRD-WEB01.health.wa.gov.au"))
        a2 = feature_vector_to_array(extract_features("per-PRD-DB01.justice.wa.gov.au"))
        assert a1 != a2, "Different hostnames should produce different arrays"

    def test_empty_hostname_returns_60_values(self):
        from ml.pretier_features import extract_features, feature_vector_to_array

        arr = feature_vector_to_array(extract_features(""))
        assert len(arr) == 60

    def test_none_hostname_raises(self):
        """None crashes extract_features; confirm it's not silently ignored."""
        from ml.pretier_features import extract_features

        with pytest.raises(AttributeError):
            extract_features(None)  # type: ignore[arg-type]


class TestGetFeatureNames:
    """Feature name metadata."""

    def test_returns_60_names(self):
        from ml.pretier_features import get_feature_names

        names = get_feature_names()
        assert len(names) == 60

    def test_all_names_are_unique(self):
        from ml.pretier_features import get_feature_names

        names = get_feature_names()
        assert len(names) == len(set(names)), "Feature names contain duplicates"

    def test_all_names_are_strings(self):
        from ml.pretier_features import get_feature_names

        for name in get_feature_names():
            assert isinstance(name, str), f"Expected str, got {type(name)}"

    def test_deterministic(self):
        from ml.pretier_features import get_feature_names

        assert get_feature_names() == get_feature_names(), (
            "get_feature_names() should be deterministic"
        )

    def test_first_name_is_env_code(self):
        from ml.pretier_features import get_feature_names

        assert get_feature_names()[0] == "env_code"

    def test_last_name_is_system_category(self):
        from ml.pretier_features import get_feature_names

        assert get_feature_names()[-1] == "system_category"


class TestGetFeatureCount:
    """Feature count metadata."""

    def test_returns_60(self):
        from ml.pretier_features import get_feature_count

        assert get_feature_count() == 60

    def test_equals_len_of_get_feature_names(self):
        from ml.pretier_features import get_feature_count, get_feature_names

        assert get_feature_count() == len(get_feature_names())
