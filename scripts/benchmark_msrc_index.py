"""Synthetic file -> index parser -> publication selection memory measurement.

Run each size in a fresh process. No network, PostgreSQL or retained evidence.
This measures discovery, not CVRF child imports or the integrated product gate.
"""

import argparse
import json
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from standalone.evidence_pipeline.parsing.msrc_publications import CONTEXT, publications
from standalone.evidence_pipeline.collection.msrc_publication_selection import (
    MONTHS,
    select_changed,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.records <= 96000:
        parser.error("Synthetic generator supports 1..96000 unique publication months")
    # Linux ru_maxrss may include memory inherited across exec. Reset the
    # process high-water mark before generating or processing the fixture.
    Path("/proc/self/clear_refs").write_text("5")
    with tempfile.TemporaryFile() as stream:
        stream.write(
            json.dumps({"@odata.context": CONTEXT})[:-1].encode() + b',"value":['
        )
        for number in range(args.records):
            identity = f"{2000 + number // 12:04d}-{MONTHS[number % 12]}"
            value = dict(
                ID=identity,
                Alias=identity,
                DocumentTitle="Synthetic " + "x" * 4096,
                Severity=None,
                InitialReleaseDate="2099-01-01T00:00:00Z",
                CurrentReleaseDate="2099-03-01T00:00:00Z",
                CvrfUrl="https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + identity,
            )
            if number:
                stream.write(b",")
            stream.write(json.dumps(value).encode())
        stream.write(b"]}")
        size = stream.tell()
        stream.seek(0)
        started = time.monotonic()
        count = sum(
            1
            for _ in select_changed(
                publications(stream),
                (),
                starting_month=None,
                retained_ids=frozenset(),
            )
        )
        assert count == args.records
        print(
            json.dumps(
                dict(
                    synthetic=True,
                    records=count,
                    input_bytes=size,
                    processing_seconds=round(time.monotonic() - started, 3),
                    peak_rss_kib=int(
                        next(
                            line.split()[1]
                            for line in Path("/proc/self/status")
                            .read_text()
                            .splitlines()
                            if line.startswith("VmHWM:")
                        )
                    ),
                    scope="file_parser_selection_only",
                )
            )
        )


if __name__ == "__main__":
    main()
