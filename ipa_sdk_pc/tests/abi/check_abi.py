#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import subprocess
import sys


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def exported_symbols(library: pathlib.Path) -> list[str]:
    output = run("nm", "-D", "--defined-only", str(library))
    symbols = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-2].upper() in {"T", "W"}:
            symbols.append(parts[-1].split("@", 1)[0])
    return sorted(set(symbols))


def soname(library: pathlib.Path) -> str:
    output = run("readelf", "-d", str(library))
    match = re.search(r"\(SONAME\).*\[([^]]+)\]", output)
    return match.group(1) if match else ""


def layout(probe: pathlib.Path) -> dict[str, int]:
    return json.loads(run(str(probe)))


def read_symbols(path: pathlib.Path) -> list[str]:
    return sorted(line.strip() for line in path.read_text().splitlines() if line.strip())


def compare(label: str, expected, actual) -> list[str]:
    if expected == actual:
        return []
    if isinstance(expected, list):
        missing = sorted(set(expected) - set(actual))
        added = sorted(set(actual) - set(expected))
        return [f"{label}: missing={missing}, added={added}"]
    keys = sorted(set(expected) | set(actual))
    return [
        f"{label}.{key}: expected={expected.get(key)!r}, actual={actual.get(key)!r}"
        for key in keys
        if expected.get(key) != actual.get(key)
    ]


def write_version_script(symbols: list[str], path: pathlib.Path) -> None:
    lines = ["IPA_1.0 {", "  global:"]
    lines.extend(f"    {symbol};" for symbol in symbols)
    lines.extend(["  local: *;", "};", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=pathlib.Path)
    parser.add_argument("--probe", type=pathlib.Path)
    parser.add_argument("--symbols", type=pathlib.Path, required=True)
    parser.add_argument("--layout", type=pathlib.Path)
    parser.add_argument("--record-layout", action="store_true")
    parser.add_argument("--expected-soname", default="libipa.so")
    parser.add_argument("--write-version-script", type=pathlib.Path)
    args = parser.parse_args()

    expected_symbols = read_symbols(args.symbols)
    if args.write_version_script:
        write_version_script(expected_symbols, args.write_version_script)
        return 0
    if not args.library or not args.probe or not args.layout:
        parser.error("--library, --probe and --layout are required for ABI comparison")

    actual_layout = layout(args.probe)
    if args.record_layout:
        args.layout.parent.mkdir(parents=True, exist_ok=True)
        args.layout.write_text(json.dumps(actual_layout, indent=2, sort_keys=True) + "\n")
        print(f"Recorded layout baseline: {args.layout}")
        return 0

    failures = []
    failures.extend(compare("symbols", expected_symbols, exported_symbols(args.library)))
    failures.extend(compare("layout", json.loads(args.layout.read_text()), actual_layout))
    actual_soname = soname(args.library)
    if actual_soname != args.expected_soname:
        failures.append(f"soname: expected={args.expected_soname!r}, actual={actual_soname!r}")
    if failures:
        print("ABI incompatible:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("ABI compatible: symbols, public layouts and SONAME match baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
