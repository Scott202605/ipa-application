#!/usr/bin/env python3
import argparse
import pathlib
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--http", type=pathlib.Path, required=True)
    parser.add_argument("--mqtt", type=pathlib.Path, required=True)
    parser.add_argument("--lwm2m", type=pathlib.Path, required=True)
    args = parser.parse_args()
    http = args.http.read_text()
    mqtt = args.mqtt.read_text()
    lwm2m = args.lwm2m.read_text()
    failures = []

    if "CURLOPT_SSL_VERIFYHOST, 2L" not in http:
        failures.append("HTTPS hostname verification is not enforced")
    if "CURLOPT_SSL_VERIFYPEER, 1L" not in http:
        failures.append("HTTPS peer verification is not enforced")
    if "CURLOPT_SSL_VERIFYHOST, 0L" in http or "CURLOPT_SSL_VERIFYPEER, 0L" in http:
        failures.append("HTTPS contains an insecure verification bypass")
    if "enableServerCertAuth = 1" not in mqtt or "ssl_connection_options.verify = 1" not in mqtt:
        failures.append("MQTT TLS server identity verification is not enforced")
    if "password [%s]" in mqtt:
        failures.append("MQTT logs plaintext passwords")
    if "if (dtls)" not in lwm2m or "return -eNotSupported" not in lwm2m:
        failures.append("unsupported LwM2M DTLS does not fail closed")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Transport verification policy is fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
