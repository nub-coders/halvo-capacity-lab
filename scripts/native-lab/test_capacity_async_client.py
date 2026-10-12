"""Real loopback/pipe checks of the nonblocking client, never lab capacity."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import resource
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity_async_client as client

ROOT = Path(__file__).resolve().parent
BODY = b"halvo-memory"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        self.server.requests.append(self.client_address[1])
        try:
            mode = self.server.mode
            if mode == "disconnect":
                self.close_connection = True
                return
            if mode == "stall":
                self.close_connection = True
                while self.connection.recv(1024):
                    pass
                self.server.closed.set()
                return
            if mode == "chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"5\r\nhalvo\r\n7\r\n-memory\r\n0\r\nX-Test: yes\r\n\r\n")
                return
            self.send_response(500 if mode == "status" else 200)
            body = b"wrong" if mode == "body" else BODY
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if mode == "trickle":
                for value in body:
                    self.wfile.write(bytes((value,)))
                    self.wfile.flush()
                    time.sleep(0.05)
            else:
                self.wfile.write(body)
            if mode == "idle-eof":
                self.close_connection = True  # No Connection:close header.
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def log_message(self, *args):
        pass


class ResponseFramingTests(unittest.TestCase):
    def test_fragmented_content_length_and_chunked_bodies(self):
        for wire in (b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n" + BODY,
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"c;test=\"quoted\"\r\n" + BODY + b"\r\n0\r\n\r\n"):
            response = client._Response()
            complete = False
            for value in wire:
                complete = response.feed(bytes((value,)))
            self.assertTrue(complete)
            self.assertEqual(response.body, BODY)
            self.assertEqual(response.version, 11)
            self.assertTrue(response.keepalive)

    def test_ambiguous_oversized_or_malformed_framing_is_rejected(self):
        for wire in (b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Length: 12\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nTransfer-Encoding: chunked\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nX:" + b"x" * 16385,
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 12\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n" + BODY + b"extra"):
            with self.subTest(wire=wire[:80]), self.assertRaises(client._BadResponse):
                client._Response().feed(wire)

    def test_nonloopback_and_invalid_bounds_are_rejected_before_execution(self):
        for host, options in (("192.0.2.1", {}), ("example.com", {}),
                              ("127.0.0.1", {"timeout": 31}),
                              ("127.0.0.1", {"max_outstanding": 4097}),
                              ("127.0.0.1", {"max_idle": 33}),
                              ("127.0.0.1", {"max_outstanding": True})):
            with self.subTest(host=host, options=options), self.assertRaises(ValueError):
                client.run(host, 3000, BODY, **options)


class AsyncClientLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.mode = "normal"
        self.server.requests = []
        self.server.closed = threading.Event()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())

    def child(self, *, timeout=1, max_outstanding=4096, max_idle=32, prefix=None, port=None):
        args = [sys.executable, "-B", str(ROOT / "capacity_async_client.py")]
        if prefix is not None:
            args = [sys.executable, "-B", "-c", prefix, str(ROOT)]
        args += ["--port", str(self.server.server_port if port is None else port), "--expected", BODY.decode(),
                 "--timeout", str(timeout), "--max-outstanding", str(max_outstanding),
                 "--max-idle", str(max_idle)]
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        def cleanup():
            if process.poll() is None:
                process.kill(); process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.addCleanup(cleanup)
        return process

    def command(self, identifier):
        return (json.dumps({"type": "request", "id": identifier,
                            "scheduled_at": time.monotonic()}) + "\n").encode()

    def ready(self, process):
        self.assertEqual(json.loads(process.stdout.readline()), {"type": "ready", "protocol": 1})

    def request(self, process, identifier):
        process.stdin.write(self.command(identifier))
        return json.loads(process.stdout.readline())

    def drain(self, process):
        process.stdin.close()
        process.wait(timeout=3)
        self.assertEqual(process.returncode, 0, process.stderr.read())

    def test_clean_content_length_and_chunked_connections_are_reused(self):
        for mode in ("normal", "chunked"):
            with self.subTest(mode=mode):
                self.server.mode = mode
                process = self.child()
                self.ready(process)
                for identifier in range(3):
                    row = self.request(process, identifier)
                    self.assertTrue(row["ok"], row)
                    self.assertEqual(row["http_version"], 11)
                    self.assertEqual(row["connection_reused"], identifier > 0)
                self.drain(process)

    def test_idle_eof_is_discarded_before_next_get_not_retried(self):
        self.server.mode = "idle-eof"
        process = self.child()
        self.ready(process)
        for identifier in range(2):
            row = self.request(process, identifier)
            self.assertTrue(row["ok"], row)
            self.assertFalse(row["connection_reused"])
            time.sleep(0.05)
        self.drain(process)
        self.assertEqual(len(self.server.requests), 2)

    def test_body_status_and_uncertain_disconnect_remain_counted_errors(self):
        for mode, error in (("body", "unexpected_response"), ("status", "http_status"),
                            ("disconnect", "transport_error")):
            with self.subTest(mode=mode):
                self.server.mode = mode
                before = len(self.server.requests)
                process = self.child()
                self.ready(process)
                row = self.request(process, 0)
                self.assertFalse(row["ok"], row)
                self.assertEqual(row["error"], error)
                self.drain(process)
                self.assertEqual(len(self.server.requests) - before, 1)

    def test_deadline_covers_entire_trickled_body_and_stalled_response(self):
        for mode in ("trickle", "stall"):
            with self.subTest(mode=mode):
                self.server.mode = mode
                process = self.child(timeout=0.2)
                self.ready(process)
                row = self.request(process, 0)
                self.assertEqual(row["error"], "timeout", row)
                elapsed = row["ended_at"] - row["started_at"]
                self.assertGreaterEqual(elapsed, 0.2)
                self.assertLess(elapsed, 0.6)
                self.drain(process)

    def test_malformed_command_causes_no_http_request(self):
        for raw in (b'{"type":"request","id":true,"scheduled_at":0}\n',
                    b'{"type":"request","id":0,"scheduled_at":NaN}\n',
                    b'{"type":"request","id":0,"id":1,"scheduled_at":0}\n',
                    b'{"type":"request","id":0,"scheduled_at":0,"extra":1}\n',
                    b'x' * 4097):
            with self.subTest(raw=raw[:70]):
                process = self.child()
                output, _ = process.communicate(raw, timeout=3)
                self.assertEqual(process.returncode, 2)
                self.assertEqual(json.loads(output.splitlines()[-1])["type"], "protocol_error")
        self.assertEqual(self.server.requests, [])

    def test_client_overflow_is_terminal_instrument_failure_not_backend_error(self):
        self.server.mode = "stall"
        process = self.child(timeout=1, max_outstanding=2)
        output, _ = process.communicate(b''.join(self.command(i) for i in range(5)), timeout=3)
        self.assertEqual(process.returncode, 2)
        records = [json.loads(line) for line in output.splitlines()]
        self.assertTrue(any(row.get("error") == "client_queue_full" for row in records))
        self.assertEqual(records[-1]["type"], "protocol_error")

    def test_low_descriptor_hard_limit_refuses_startup_without_http(self):
        self.server.mode = "stall"
        prefix = ("import resource,sys; resource.setrlimit(resource.RLIMIT_NOFILE,(32,32)); "
                  "sys.path.insert(0,sys.argv.pop(1)); import capacity_async_client; "
                  "raise SystemExit(capacity_async_client.main())")
        process = self.child(prefix=prefix)
        output, _ = process.communicate(b''.join(self.command(i) for i in range(100)), timeout=3)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(output, b"")
        self.assertEqual(self.server.requests, [])

    def test_only_child_soft_descriptor_limit_is_raised(self):
        original = resource.getrlimit(resource.RLIMIT_NOFILE)
        prefix = ("import resource,sys; s,h=resource.getrlimit(resource.RLIMIT_NOFILE); "
                  "resource.setrlimit(resource.RLIMIT_NOFILE,(32,h)); "
                  "sys.path.insert(0,sys.argv.pop(1)); import capacity_async_client; "
                  "raise SystemExit(capacity_async_client.main())")
        process = self.child(prefix=prefix)
        self.ready(process)
        soft, hard = resource.prlimit(process.pid, resource.RLIMIT_NOFILE)
        self.assertGreaterEqual(soft, 8192)
        self.assertEqual(hard, original[1])
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE), original)
        self.assertTrue(self.request(process, 0)["ok"])
        self.drain(process)

    def test_runtime_fd_exhaustion_is_not_counted_as_backend_failure(self):
        self.server.mode = "stall"
        process = self.child()
        self.ready(process)
        _, hard = resource.prlimit(process.pid, resource.RLIMIT_NOFILE)
        resource.prlimit(process.pid, resource.RLIMIT_NOFILE, (32, hard))
        output, _ = process.communicate(b''.join(self.command(i) for i in range(100)), timeout=3)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(output.splitlines()[-1]),
                         {"type": "protocol_error", "error": "client_resource_error"})

    def test_unread_output_stalls_are_bounded_and_close_owned_clients(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            unused = reservation.getsockname()[1]
        process = self.child(timeout=0.2, port=unused)
        self.ready(process)
        commands = b''.join(self.command(i) for i in range(1000))
        def feed():
            try:
                offset = 0
                while offset < len(commands):
                    offset += process.stdin.write(commands[offset:])
            except (BrokenPipeError, OSError):
                pass
            finally:
                process.stdin.close()
        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        process.wait(timeout=3)  # Deliberately do not consume stdout.
        writer.join(1)
        self.assertFalse(writer.is_alive())
        self.assertEqual(process.returncode, 2)

    def test_sigterm_closes_owned_socket_under_bounded_shutdown(self):
        self.server.mode = "stall"
        process = self.child(timeout=30)
        self.ready(process)
        process.stdin.write(self.command(0))
        deadline = time.monotonic() + 3
        while not self.server.requests and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.server.requests)
        process.terminate()
        process.wait(timeout=3)
        self.assertEqual(process.returncode, 2)
        self.assertTrue(self.server.closed.wait(1))
        self.assertEqual(json.loads(process.stdout.readline()),
                         {"type": "protocol_error", "error": "interrupted"})


if __name__ == "__main__":
    unittest.main()
