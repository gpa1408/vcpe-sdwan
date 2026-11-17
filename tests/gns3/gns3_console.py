#!/usr/bin/env python3
"""GNS3 CI: inspect, test, or explicitly restore CPE namespaces.

Requires Python 3.12 and requests. Default mode is read-only.
Only --recover-both can change a CPE's namespace configuration.
"""

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import sys
import time
import uuid
import warnings
from urllib.parse import urlparse

import requests

EXPECTED_PROJECT = "sdwan-ci"
SCRIPT_FILE = Path(__file__).with_name("setup_namespace.sh")
SCRIPT_URL = (
    "https://raw.githubusercontent.com/"
    "MuhammadImran1045/vcpe-sdwan/feature/gns3-ci-automation/"
    "tests/gns3/setup_namespace.sh"
)
REMOTE_SCRIPT = "/tmp/setup_namespace.sh"
DEVICES = {
    "CPE-1": {"mode": "cpe1", "ns": "ci-ns1", "iface": "veth-ns1", "net": "10.0.1.0/24", "gw": "10.0.1.1"},
    "CPE-2": {"mode": "cpe2", "ns": "ci-ns2", "iface": "veth-ns2", "net": "10.0.2.0/24", "gw": "10.0.2.1"},
}


def get_json(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


def discover(name):
    url = os.environ.get("GNS3_URL", "").rstrip("/")
    project_id = os.environ.get("GNS3_PROJECT_ID", "").strip()
    if not url or not project_id or urlparse(url).scheme not in ("http", "https"):
        raise RuntimeError("Set valid GNS3_URL and GNS3_PROJECT_ID environment variables")

    base = f"{url}/v2/projects/{project_id}"
    project = get_json(base)
    if project.get("name") != EXPECTED_PROJECT:
        raise RuntimeError("Safety check failed: unexpected GNS3 project")
    matches = [n for n in get_json(base + "/nodes") if n.get("name") == name]
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {name}, found {len(matches)}")
    node = matches[0]
    if node.get("node_type") != "qemu" or node.get("console_type") != "telnet":
        raise RuntimeError(f"Unexpected device or console type for {name}")
    if node.get("status") not in ("started", "running"):
        raise RuntimeError(f"{name} is not running (status: {node.get('status')})")
    port = node.get("console")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise RuntimeError(f"Invalid console port for {name}")
    host = os.environ.get("GNS3_CONSOLE_HOST") or urlparse(url).hostname
    if not host:
        raise RuntimeError("No GNS3 console host found")
    return host, port


def clean_lines(data):
    output = data.decode("utf-8", errors="replace")
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
    return [line.strip() for line in output.replace("\r", "").splitlines()]


def run_command(session, command, timeout=25):
    """Collect command output and its exit code using unique shell markers."""
    token = uuid.uuid4().hex[:12]
    begin, end = f"CI_BEGIN_{token}", f"CI_END_{token}"
    payload = (
        f"printf '\\n{begin}\\n'; "
        f"{command}; "
        f"ci_status=$?; printf '\\n{end}:%s\\n' \"$ci_status\""
    )
    session.write(payload.encode("ascii") + b"\r\n")
    data = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.15)
        try:
            data.extend(session.read_very_eager())
        except EOFError as exc:
            raise RuntimeError("GNS3 console closed the connection") from exc
        lines = clean_lines(data)
        if begin not in lines:
            continue
        start = lines.index(begin)
        for i in range(start + 1, len(lines)):
            match = re.fullmatch(re.escape(end) + r":(\d+)", lines[i])
            if not match:
                continue
            result = "\n".join(lines[start + 1:i]).strip()
            code = int(match.group(1))
            if code != 0:
                raise RuntimeError(f"Command failed (exit {code}): {command}\n{result}")
            return result
    raise RuntimeError(f"Timed out waiting for: {command}")


def connect_console(host, port):
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("Console control requires Python 3.12 (telnetlib)")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import telnetlib
    session = telnetlib.Telnet(host, port, timeout=6)
    try:
        time.sleep(0.3)
        session.read_very_eager()
        session.write(b"\r\n")
        time.sleep(0.3)
        session.read_very_eager()
    except EOFError as exc:
        session.close()
        raise RuntimeError("Console disconnected; close other console clients") from exc
    return session


def probe(session):
    result = run_command(session, "uname -s")
    if "Linux" not in result.splitlines():
        raise RuntimeError(f"Unexpected uname result: {result!r}")
    print("PASS: Console executed uname -s (Linux)")


def namespace_test(session, name):
    config = DEVICES[name]
    ns, iface, gateway = config["ns"], config["iface"], config["gw"]
    print(f"Checking namespace: {ns}")
    listing = run_command(session, "ip netns list")
    names = [line.split()[0] for line in listing.splitlines() if line.split()]
    if ns not in names:
        raise RuntimeError(f"Namespace {ns} not found")
    print("PASS: Namespace exists")

    addresses = run_command(session, f"ip netns exec {ns} ip -4 -o addr show dev {iface}")
    expected = ipaddress.ip_network(config["net"])
    found = re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b", addresses)
    valid = [ipaddress.ip_interface(x) for x in found
             if ipaddress.ip_interface(x).network == expected]
    if not valid:
        raise RuntimeError(f"No IPv4 address in {expected} on {iface}: {addresses}")
    print(f"PASS: Namespace IP {valid[0]}")

    ping = run_command(session, f"ip netns exec {ns} ping -c 3 -W 2 {gateway}", timeout=20)
    match = re.search(
        r"(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+(?:packets?\s+)?received,\s*(\d+)%\s+packet loss",
        ping,
    )
    if not match or tuple(map(int, match.groups())) != (3, 3, 0):
        raise RuntimeError(f"Gateway ping failed or output unknown:\n{ping}")
    print(f"PASS: Gateway {gateway}, 3/3 replies, 0% loss")


def local_script_sha256():
    if not SCRIPT_FILE.is_file():
        raise RuntimeError(f"Local script not found: {SCRIPT_FILE}")
    script = SCRIPT_FILE.read_bytes().replace(b"\r\n", b"\n")
    if not script.lstrip(bytes([10,13])).startswith(b"#!/bin/sh\n"):
        raise RuntimeError("Local script has an unexpected header")
    return hashlib.sha256(script).hexdigest()


def recover_namespace(session, name, digest):
    """Explicitly install/run the previously tested setup_namespace.sh."""
    print(f"Restoring {DEVICES[name]['ns']} using the verified script...")
    run_command(session, f"wget -T 10 -O {REMOTE_SCRIPT} {SCRIPT_URL}", timeout=35)
    remote_hash = run_command(session, f"sha256sum {REMOTE_SCRIPT}")
    match = re.search(r"\b([0-9a-f]{64})\b", remote_hash)
    if not match or match.group(1) != digest:
        raise RuntimeError("Downloaded script hash differs from local file; NOT executing")
    print("PASS: Downloaded script SHA-256 matches local file")
    run_command(session, f"sh -n {REMOTE_SCRIPT}")
    print("PASS: Remote shell syntax valid")
    result = run_command(
        session,
        f"sh {REMOTE_SCRIPT} {DEVICES[name]['mode']}",
        timeout=55,
    )
    if "PASS: Namespace connectivity successful" not in result:
        raise RuntimeError(f"Setup script did not report PASS:\n{result}")
    print("PASS: Namespace setup script completed")
    namespace_test(session, name)


def main():
    parser = argparse.ArgumentParser(description="SD-WAN GNS3 console CI checks")
    parser.add_argument("--device", choices=tuple(DEVICES), default="CPE-1")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--probe", action="store_true", help="Read-only Linux probe")
    group.add_argument("--test", action="store_true", help="Read-only namespace test on one CPE")
    group.add_argument("--test-both", action="store_true", help="Read-only tests on both CPEs")
    group.add_argument("--recover-both", action="store_true",
                       help="CHANGES CPEs: download, verify and run namespace setup script on both")
    args = parser.parse_args()
    names = list(DEVICES) if args.test_both or args.recover_both else [args.device]
    digest = local_script_sha256() if args.recover_both else None
    failures = []
    for name in names:
        print(f"\n=== {name} / {EXPECTED_PROJECT} ===", flush=True)
        try:
            host, port = discover(name)
            print(f"Console: {host}:{port}")
            if not (args.probe or args.test or args.test_both or args.recover_both):
                print("PASS: Read-only API inspection; no console commands sent")
                continue
            with connect_console(host, port) as session:
                if args.probe:
                    probe(session)
                elif args.recover_both:
                    recover_namespace(session, name, digest)
                else:
                    namespace_test(session, name)
        except (RuntimeError, OSError, requests.RequestException) as exc:
            print(f"FAIL: {exc}")
            failures.append(name)
    if failures:
        print(f"\nCI RESULT: FAIL ({', '.join(failures)})")
        return 1
    print("\nCI RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
