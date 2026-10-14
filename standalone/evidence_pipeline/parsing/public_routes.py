"""Validate source identifiers and derive fixed public URLs without network I/O."""

import re
from urllib.parse import quote


def endpoint(
    source: str,
    cve: str | None = None,
    *,
    month: str | None = None,
    score_date: str | None = None,
    input_kind: str | None = None,
    advisory_id: str | None = None,
    repository_commit: str | None = None,
    repository_path: str | None = None,
    vendor_path: str | None = None,
) -> str:
    if score_date is not None:
        from standalone.evidence_pipeline.epss_route import archive_url

        if (
            source != "FIRST"
            or input_kind not in (None, "epss")
            or any(
                value is not None
                for value in (
                    cve,
                    month,
                    advisory_id,
                    repository_commit,
                    repository_path,
                    vendor_path,
                )
            )
        ):
            raise ValueError("EPSS archive date requires an unambiguous FIRST route")
        return archive_url(score_date)
    if source == "Ubuntu" and (
        repository_commit is not None or repository_path is not None
    ):
        from standalone.evidence_pipeline.parsing.ubuntu_advisories import (
            repository_endpoint,
        )

        if input_kind != "advisories" or any(
            value is not None for value in (cve, month, vendor_path)
        ):
            raise ValueError("Ubuntu repository collection cannot mix source routes")
        return repository_endpoint(repository_commit, repository_path, advisory_id)
    if source == "Red Hat" or vendor_path is not None:
        from standalone.evidence_pipeline.parsing.redhat_discovery import advisory_file

        if (source, input_kind) != ("Red Hat", "advisories") or any(
            value is not None
            for value in (cve, month, advisory_id, repository_commit, repository_path)
        ):
            raise ValueError("Red Hat collection requires its exact index path only")
        return advisory_file(vendor_path).url
    if (source, input_kind) in {("CVE", "records"), ("CISA", "vulnrichment")} and (
        repository_commit is not None or repository_path is not None
    ):
        from standalone.evidence_pipeline.parsing.cve_discovery import record_url

        if month is not None or advisory_id is not None:
            raise ValueError("CVE repository collection cannot mix source routes")
        return record_url(source, repository_commit, repository_path, cve)
    if (
        source == "GitHub"
        or repository_commit is not None
        or repository_path is not None
    ):
        from standalone.evidence_pipeline.parsing.github_advisories import (
            endpoint as github_endpoint,
        )

        if (source, input_kind) != ("GitHub", "advisories") or any(
            value is not None for value in (cve, month, advisory_id)
        ):
            raise ValueError("GitHub repository collection cannot mix source routes")
        return github_endpoint(repository_commit, repository_path)
    if source == "Ubuntu":
        from standalone.evidence_pipeline.parsing.ubuntu_advisories import (
            endpoint as ubuntu_endpoint,
        )

        if input_kind != "advisories" or cve is not None or month is not None:
            raise ValueError("Ubuntu collection requires a native advisory ID only")
        return ubuntu_endpoint(advisory_id)
    if advisory_id is not None or source == "OSV":
        if (
            (source, input_kind) != ("OSV", "advisories")
            or cve is not None
            or month is not None
            or not isinstance(advisory_id, str)
            or len(advisory_id) > 256
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._+\-]*", advisory_id)
        ):
            raise ValueError("OSV collection requires one valid native advisory ID")
        return "https://api.osv.dev/v1/vulns/" + quote(advisory_id, safe="")
    from standalone.evidence_pipeline.parsing import (
        attack_definitions,
        ctid_mappings,
        exploit_db,
    )

    references = {
        ("MITRE ATT&CK", "enterprise_definitions"): attack_definitions.URL,
        ("CTID", "cve_mappings"): ctid_mappings.URL,
        ("Exploit-DB", "metadata"): exploit_db.URL,
    }
    if (source, input_kind) in references:
        if cve is not None or month is not None:
            raise ValueError(
                "Reference collection does not accept CVE or month filters"
            )
        return references[source, input_kind]
    if (source, input_kind) in {("CVE", "records"), ("CISA", "vulnrichment")}:
        if (
            month is not None
            or not isinstance(cve, str)
            or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve)
        ):
            raise ValueError("CVE record collection requires one valid CVE identifier")
        _, year, sequence = cve.split("-")
        repository = (
            "CVEProject/cvelistV5/main/cves"
            if source == "CVE"
            else "cisagov/vulnrichment/develop"
        )
        return (
            f"https://raw.githubusercontent.com/{repository}/"
            f"{year}/{sequence[:-3]}xxx/{cve}.json"
        )
    if input_kind is not None and (source, input_kind) not in {
        ("MSRC", "security_updates" if month is not None else "advisories"),
        ("FIRST", "epss"),
        ("CISA", "kev"),
        ("NVD", "vulnerabilities"),
    }:
        raise ValueError("Unsupported public source input kind")
    if month is not None:
        from standalone.evidence_pipeline.parsing.msrc_publications import (
            PUBLICATION_ID,
        )

        if (
            source != "MSRC"
            or cve is not None
            or not isinstance(month, str)
            or PUBLICATION_ID.fullmatch(month) is None
        ):
            raise ValueError("Update collection requires one MSRC publication ID")
        return "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + month
    if source in ("NVD", "MSRC"):
        if not isinstance(cve, str) or not re.fullmatch(
            r"CVE-[0-9]{4}-[0-9]{4,19}", cve
        ):
            raise ValueError(
                "Advisory/vulnerability collection requires one valid CVE identifier"
            )
        if source == "MSRC":
            return f"https://msrc.microsoft.com/csaf/advisories/{cve.split('-')[1]}/msrc_{cve.lower()}.json"
        return "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
    if cve is not None:
        raise ValueError("CVE filtering applies only to NVD and MSRC requests")
    urls = {
        "FIRST": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "CISA": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    }
    if source not in urls:
        raise ValueError("Unsupported public source")
    return urls[source]
