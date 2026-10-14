"""Direct ctypes binding to the pinned libpg_query PostgreSQL 16 JSON parser."""

import ctypes as c
from functools import lru_cache
import os
from pathlib import Path

LIBRARY = Path(__file__).resolve().parents[2] / "ui-engine/work/parser/libpg_query.so"


class ParseError(ValueError):
    pass


class Error(c.Structure):
    _fields_ = [
        ("message", c.c_char_p),
        ("funcname", c.c_char_p),
        ("filename", c.c_char_p),
        ("lineno", c.c_int),
        ("cursorpos", c.c_int),
        ("context", c.c_char_p),
    ]


class Result(c.Structure):
    _fields_ = [
        ("parse_tree", c.c_char_p),
        ("stderr_buffer", c.c_char_p),
        ("error", c.POINTER(Error)),
    ]


def library_path():
    """Use an explicit retained artifact or the existing workstation default."""
    configured = os.environ.get("TRIAGEMATE_PG_PARSER_LIBRARY")
    if configured is None:
        return LIBRARY
    path = Path(configured)
    if not path.is_absolute():
        raise OSError("TRIAGEMATE_PG_PARSER_LIBRARY must be an absolute file path")
    if not path.is_file():
        raise OSError("Configured PostgreSQL parser library is missing")
    return path


@lru_cache(maxsize=1)
def library():
    # Only a prepared local artifact: no system search, build, or download.
    lib = c.CDLL(str(library_path()))
    lib.pg_query_parse.argtypes = [c.c_char_p]
    lib.pg_query_parse.restype = Result
    lib.pg_query_free_parse_result.argtypes = [Result]
    lib.pg_query_free_parse_result.restype = None
    return lib


def parse_sql_json(source):
    # Reject NUL before the C API can silently parse only a prefix of the input.
    if "\0" in source:
        raise ParseError("SQL cannot contain a NUL character.")
    data = source.encode("utf-8", errors="strict")
    lib = library()
    result = lib.pg_query_parse(data)
    try:
        if result.error:
            error = result.error.contents
            message = error.message.decode("utf-8", errors="replace")
            raise ParseError(f"{message} (position {error.cursorpos})")
        if not result.parse_tree:
            raise ParseError("PostgreSQL parser returned no syntax tree.")
        return result.parse_tree.decode("utf-8", errors="strict")
    finally:
        lib.pg_query_free_parse_result(result)
        # The upstream pthread destructor releases the top context at thread exit.
        # pg_query_exit is terminal-only, not safe between parses on one thread.
