#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^)]*\)\s*\{{", source)
    if not match:
        raise AssertionError(f"function not found: {name}")
    start = match.end()
    depth = 1
    cursor = start
    while cursor < len(source) and depth:
        depth += source[cursor] == "{"
        depth -= source[cursor] == "}"
        cursor += 1
    if depth:
        raise AssertionError(f"unterminated function: {name}")
    return source[start : cursor - 1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", type=pathlib.Path, required=True)
    args = parser.parse_args()
    source = args.wrapper.read_text(errors="replace")
    names = [
        "ipad_wrapper_profile_download",
        "ipad_wrapper_profile_enable",
        "ipad_wrapper_profile_disable",
        "ipad_wrapper_profile_delete",
    ]
    failures = [name for name in names if "return eNotImpl;" not in function_body(source, name)]
    if failures:
        print("Manager placeholder behavior changed: " + ", ".join(failures),
              file=sys.stderr)
        return 1
    print("Manager profile lifecycle placeholders still return eNotImpl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
