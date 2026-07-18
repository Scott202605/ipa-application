#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys


TYPE_PATTERNS = {
    "ipa_event_type_t": r"typedef\s+enum\s*\{(?P<body>[^}]*)\}\s*ipa_event_type_t\s*;",
    "es10_driver_type_t": r"typedef\s+enum\s+es10_driver_type_e\s*\{(?P<body>[^}]*)\}\s*es10_driver_type_t\s*;",
    "cl_config_t": r"typedef\s+struct\s+cl_config_s\s*\{(?P<body>[^}]*)\}\s*cl_config_t\s*;",
    "ipa_config_mqtt_t": r"typedef\s+struct\s+ipa_config_mqtt_s\s*\{(?P<body>[^}]*)\}\s*ipa_config_mqtt_t\s*;",
    "ipa_config_lwm2m_t": r"typedef\s+struct\s+ipa_config_lwm2m_s\s*\{(?P<body>[^}]*)\}\s*ipa_config_lwm2m_t\s*;",
    "ipa_config_http_t": r"typedef\s+struct\s+ipa_config_http_s\s*\{(?P<body>[^}]*)\}\s*ipa_config_http_t\s*;",
    "ipa_task_callbacks_t": r"typedef\s+struct\s*\{(?P<body>[^}]*task_start_cb[^}]*task_end_cb[^}]*)\}\s*ipa_task_callbacks_t\s*;",
}


def normalize(body: str) -> str:
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.DOTALL)
    return " ".join(re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|\*|\[|\]|;|,", body))


def extract(source: str, name: str, pattern: str) -> str:
    match = re.search(pattern, source, re.DOTALL)
    if not match:
        raise ValueError(f"Missing type definition: {name}")
    return normalize(match.group("body"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public", type=pathlib.Path, required=True)
    parser.add_argument("--internal", type=pathlib.Path, required=True)
    args = parser.parse_args()
    public = args.public.read_text()
    internal = args.internal.read_text()
    mismatches = []
    for name, pattern in TYPE_PATTERNS.items():
        try:
            public_body = extract(public, name, pattern)
            internal_body = extract(internal, name, pattern)
        except ValueError as error:
            mismatches.append(str(error))
            continue
        if public_body != internal_body:
            mismatches.append(
                f"{name}: public={public_body!r}, internal={internal_body!r}"
            )
    if mismatches:
        print("Public/internal ABI type drift:", file=sys.stderr)
        print("\n".join(mismatches), file=sys.stderr)
        return 1
    print("Public and internal ABI type definitions match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
