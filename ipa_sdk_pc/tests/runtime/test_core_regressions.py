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
    index = start
    while index < len(source) and depth:
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    if depth:
        raise AssertionError(f"unterminated function: {name}")
    return source[start : index - 1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text()
    failures = []

    lwm2m = function_body(source, "disconnect_lwm2m_service")
    if "g_esipa_lwm2m->super" not in lwm2m:
        failures.append("LwM2M disconnect does not use g_esipa_lwm2m")
    if "g_esipa_mqtt->super" in lwm2m:
        failures.append("LwM2M disconnect incorrectly uses g_esipa_mqtt")

    init_worker = function_body(source, "ipa_init_thread_func")
    expected_assignments = (
        "es10_driver_selected = config->es10_driver_selected;",
        "es10_driver_selected = config->driver_type;",
    )
    if not any(assignment in init_worker for assignment in expected_assignments):
        failures.append("initialization does not snapshot selected ES10 driver")
    if "es10_driver_selected = ES10_DRIVER_NONE;" not in init_worker:
        failures.append("initialization failure does not reset selected ES10 driver")

    deinit = function_body(source, "ipa_deinit_library")
    if "es10_driver_selected = ES10_DRIVER_NONE;" not in deinit:
        failures.append("deinitialization does not reset selected ES10 driver")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Core service and driver cleanup regressions are guarded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
