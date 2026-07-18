#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys


PUBLIC_TYPE_PATTERNS = {
    "ipa_event_type_t": r"typedef\s+enum\s*\{[^}]*\}\s*ipa_event_type_t\s*;",
    "es10_driver_type_t": r"typedef\s+enum\s+es10_driver_type_e\s*\{[^}]*\}\s*es10_driver_type_t\s*;",
    "cl_config_t": r"typedef\s+struct\s+cl_config_s\s*\{[^}]*\}\s*cl_config_t\s*;",
    "ipa_config_mqtt_t": r"typedef\s+struct\s+ipa_config_mqtt_s\s*\{[^}]*\}\s*ipa_config_mqtt_t\s*;",
    "ipa_config_lwm2m_t": r"typedef\s+struct\s+ipa_config_lwm2m_s\s*\{[^}]*\}\s*ipa_config_lwm2m_t\s*;",
    "ipa_config_http_t": r"typedef\s+struct\s+ipa_config_http_s\s*\{[^}]*\}\s*ipa_config_http_t\s*;",
    "ipa_task_callbacks_t": r"typedef\s+struct\s*\{[^}]*\}\s*ipa_task_callbacks_t\s*;",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--internal", type=pathlib.Path, required=True)
    args = parser.parse_args()
    source = args.internal.read_text()
    duplicates = [
        name
        for name, pattern in PUBLIC_TYPE_PATTERNS.items()
        if re.search(pattern, source, re.DOTALL)
    ]
    if duplicates:
        print(
            "Internal header duplicates canonical public ABI types: "
            + ", ".join(duplicates),
            file=sys.stderr,
        )
        return 1
    print("Internal header uses canonical public ABI types")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
