"""Current collection scope; retained source metadata never activates a collector."""

DEFERRED_SOURCES = frozenset(
    {
        "Cisco",
        "Palo Alto Networks",
        "Red Hat",
        "Ubuntu",
        "Debian",
        "Apache HTTP Server",
        "Apache Tomcat",
        "Samba",
        "GitHub",
        "OSV",
        "Exploit-DB",
        "CTID",
        "MITRE ATT&CK",
    }
)


def require_active_collection(source, *, score_date=None):
    if source in DEFERRED_SOURCES or (source == "FIRST" and score_date is not None):
        raise ValueError(
            "Collector is deferred outside Sprint 1.1 and Sprint 2; "
            "reopening requires a user scope and timing decision after 23 September 2026"
        )
