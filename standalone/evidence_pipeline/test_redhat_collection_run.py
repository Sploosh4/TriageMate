"""Generated index-to-advisory batches resume using the same immutable evidence."""

import json


from .test_redhat_advisories import document

INDEX = b"2099/rhsa-2099_1234.json\n2099/rhsa-2099_5678.json\n"


def fixtures():
    result = {}
    for number in ("1234", "5678"):
        raw = document()
        raw["document"]["tracking"]["id"] = "RHSA-2099:" + number
        result["2099/rhsa-2099_" + number + ".json"] = json.dumps(raw).encode()
    return result
