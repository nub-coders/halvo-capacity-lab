#!/usr/bin/env python3
"""Capacity-only fixtures; the accepted idle/build fixture bytes are unchanged."""
import argparse
from copy import deepcopy
import json
from pathlib import Path

import benchmark

FIXTURES = deepcopy(benchmark.FIXTURES)
# A single process with bounded connection handlers. A serial TCPServer would
# hold its first persistent connection indefinitely and starve the other three
# clients. Both backends use these identical bytes under the original quotas.
PYTHON_SERVER = """from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
import threading

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True
    def do_GET(self):
        body = b'halvo-memory'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

class Server(ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32
    # Match the fixed guest relay's connection bound. A smaller synthetic cap
    # would turn slow TCG response time into fixture-generated transport errors.
    slots = threading.BoundedSemaphore(32)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

with Server(('127.0.0.1', 3000), Handler) as server:
    server.serve_forever()
"""
FIXTURES["python"]["files"]["server.py"] = PYTHON_SERVER


def write_fixtures(root):
    for fixture in FIXTURES.values():
        for name, content in fixture["files"].items():
            path = Path(root) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o644)


def deployed_digest(root, name):
    return benchmark.fixture_digest({"files": {
        filename: (Path(root) / filename).read_text() for filename in FIXTURES[name]["files"]}})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fixture-digest", choices=FIXTURES)
    group.add_argument("--identity", choices=benchmark.BINARIES)
    args = parser.parse_args()
    # Image identity must hash the deployed files, not the expected declarations.
    value = (deployed_digest('/app', args.fixture_digest) if args.fixture_digest
             else benchmark.runtime_identity(args.identity))
    print(json.dumps(value, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
