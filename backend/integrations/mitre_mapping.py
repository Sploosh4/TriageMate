"""
MITRE ATT&CK technique lookup via CWE classification.

Static mapping of CWEs to relevant ATT&CK techniques.
Used in the ingest pipeline to populate mitre_techniques_json.
"""

import logging

logger = logging.getLogger("triagemate.mitre")

CWE_TO_TECHNIQUES: dict[str, list[dict]] = {
    "CWE-89": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "desc": "SQL injection in public-facing application enables unauthenticated database access.",
        },
        {
            "id": "T1505.003",
            "name": "Server Software Component: Web Shell",
            "desc": "Post-exploitation web shell deployment for persistent access and data exfiltration.",
        },
    ],
    "CWE-79": [
        {
            "id": "T1059.007",
            "name": "Command and Scripting Interpreter: JavaScript",
            "desc": "Cross-site scripting enables execution of JavaScript in victim browser context.",
        },
        {
            "id": "T1071.001",
            "name": "Web Protocols",
            "desc": "Stolen session data exfiltrated over standard web protocols.",
        },
    ],
    "CWE-787": [
        {
            "id": "T1203",
            "name": "Exploitation for Client Execution",
            "desc": "Buffer overflow in client application enables remote code execution.",
        },
    ],
    "CWE-416": [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "desc": "Use-after-free enables privilege escalation in kernel or application context.",
        },
    ],
    "CWE-78": [
        {
            "id": "T1202",
            "name": "Indirect Command Execution",
            "desc": "OS command injection enables arbitrary command execution on the target.",
        },
    ],
    "CWE-20": [
        {
            "id": "T1574",
            "name": "Hijack Execution Flow",
            "desc": "Input validation bypass enables execution flow hijacking.",
        },
    ],
    "CWE-125": [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "desc": "Out-of-bounds read enables information disclosure for privilege escalation.",
        },
    ],
    "CWE-22": [
        {
            "id": "T1007",
            "name": "System Service Discovery",
            "desc": "Path traversal enables reading of arbitrary files on the server.",
        },
    ],
    "CWE-352": [
        {
            "id": "T1204.001",
            "name": "User Execution: Malicious Link",
            "desc": "CSRF tricks authenticated user into executing unintended actions.",
        },
    ],
    "CWE-434": [
        {
            "id": "T1505.003",
            "name": "Server Software Component: Web Shell",
            "desc": "Unrestricted file upload enables web shell deployment.",
        },
    ],
    "CWE-862": [
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "desc": "Missing authorisation check enables privilege escalation.",
        },
    ],
    "CWE-287": [
        {
            "id": "T1078",
            "name": "Valid Accounts",
            "desc": "Authentication bypass enables unauthorised access as any user.",
        },
    ],
    "CWE-190": [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "desc": "Integer overflow enables heap corruption and code execution.",
        },
    ],
    "CWE-502": [
        {
            "id": "T1203",
            "name": "Exploitation for Client Execution",
            "desc": "Deserialisation of untrusted data enables remote code execution.",
        },
    ],
    "CWE-77": [
        {
            "id": "T1202",
            "name": "Indirect Command Execution",
            "desc": "Command injection in web application enables remote code execution.",
        },
    ],
    "CWE-119": [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "desc": "Buffer overflow enables code execution in process context.",
        },
    ],
    "CWE-798": [
        {
            "id": "T1078.001",
            "name": "Default Accounts",
            "desc": "Hardcoded credentials enable unauthorised access to the device.",
        },
    ],
    "CWE-918": [
        {
            "id": "T1005",
            "name": "Data from Local System",
            "desc": "Server-side request forgery enables internal network scanning and data access.",
        },
    ],
    "CWE-306": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "desc": "Missing authentication on critical endpoint enables unauthorised access.",
        },
    ],
    "CWE-362": [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "desc": "Time-of-check time-of-use race condition enables privilege escalation.",
        },
    ],
    "CWE-269": [
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "desc": "Improper privilege management enables privilege escalation.",
        },
    ],
    "CWE-94": [
        {
            "id": "T1203",
            "name": "Exploitation for Client Execution",
            "desc": "Code injection vulnerability enables arbitrary code execution.",
        },
    ],
    "CWE-863": [
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "desc": "Incorrect authorisation enables unauthorised access to restricted resources.",
        },
    ],
    "CWE-276": [
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "desc": "Default insecure permissions enable local privilege escalation.",
        },
    ],
}


def get_techniques(cwe_class: str) -> list[dict]:
    """Look up MITRE ATT&CK techniques for a given CWE class.

    Returns a list of technique dicts with id, name, and desc keys.
    Falls back to an empty list for unknown or empty CWE.
    """
    if not cwe_class:
        return []
    result = CWE_TO_TECHNIQUES.get(cwe_class, [])
    if not result:
        logger.warning("No MITRE techniques mapped for CWE class %s", cwe_class)
    return result


def lookup_mitre(cwe_class: str) -> list[dict]:
    """Alias for get_techniques. Returns techniques for the ingest pipeline."""
    return get_techniques(cwe_class)
