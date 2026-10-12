#!/usr/bin/env python3
"""Small stdlib-only HTTP client used by the disposable capacity collector.

The parent collector enters a fixture's network namespace with ``nsenter`` and
starts one of these clients there.  The client process never enters the
fixture's cgroup; it only shares the fixture's network namespace.  Requests
are supplied as bounded JSON lines and results contain no response body.
"""

import argparse
import http.client
import io
import ipaddress
import json
import math
import queue
import select
import socket
import sys
import threading
import time


MAX_LINE_BYTES = 4096
MAX_BODY_BYTES = 4096
PROTOCOL_VERSION = 1


class _DeadlineReader(io.RawIOBase):
    def __init__(self, owner, raw):
        self.owner, self.raw = owner, raw

    def readable(self):
        return True

    def readinto(self, buffer):
        self.owner.set_remaining_timeout()
        return self.raw.readinto(buffer)

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    """Refresh the remaining budget at every underlying send/read, not per body."""
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def set_remaining_timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.sock.settimeout(remaining)

    def sendall(self, data):
        self.set_remaining_timeout()
        self.sock.sendall(data)

    def makefile(self, mode):
        # An unbuffered SocketIO makes each receive refresh its deadline.  Its
        # socket reference also survives HTTPConnection closing on Connection: close.
        return io.BufferedReader(_DeadlineReader(self, self.sock.makefile(mode, buffering=0)))


def _write(value, lock):
    """Write one compact, finite JSON record without leaking exception text."""
    payload = (json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n").encode()
    with lock:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()


def _request(command, host, port, expected, timeout, output_lock, connection):
    request_id = command.get("id")
    scheduled_at = command.get("scheduled_at")
    started_at = time.monotonic()
    # Servers may close an idle keep-alive connection (Node defaults to 5s).
    # Observe EOF before issuing the next GET, not after sending/retrying it.
    # This never retries a request whose outcome could be uncertain.
    if connection is not None and connection.sock is not None:
        try:
            readable, _, _ = select.select([connection.sock], [], [], 0)
            if readable and connection.sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b"":
                connection.close()
                connection = None
        except OSError:
            connection.close()
            connection = None
    result = {
        "type": "result",
        "id": request_id,
        "scheduled_at": scheduled_at,
        "started_at": started_at,
        "ended_at": None,
        "status": None,
        "ok": False,
        "error": None,
        "http_version": None,
        "connection_reused": connection is not None and connection.sock is not None,
    }
    deadline = started_at + timeout
    reusable = False
    response = None
    try:
        if connection is None:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        if connection.sock is None:
            connection.timeout = max(0.001, deadline - time.monotonic())
            connection.connect()
            connection.sock = _DeadlineSocket(connection.sock, deadline)
        else:
            connection.sock.deadline = deadline
        connection.request("GET", "/", headers={"Connection": "keep-alive"})
        response = connection.getresponse()
        body = response.read(MAX_BODY_BYTES + 1)
        if time.monotonic() >= deadline:
            raise TimeoutError
        result["status"] = response.status
        result["http_version"] = response.version
        reusable = not response.will_close and response.isclosed()
        if response.version != 11:
            result["error"] = "unexpected_http_version"
            reusable = False
        elif len(body) > MAX_BODY_BYTES or body != expected:
            result["error"] = "unexpected_response"
            reusable = False
        elif response.status != 200:
            result["error"] = "http_status"
        else:
            result["ok"] = True
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        reusable = False
    except (OSError, http.client.HTTPException, ValueError):
        result["error"] = "transport_error"
        reusable = False
    except BaseException:
        reusable = False
        raise
    finally:
        try:
            if response is not None:
                response.close()
        except BaseException:
            reusable = False
            raise
        finally:
            if connection is not None and not reusable:
                connection.close()
                connection = None
        result["ended_at"] = time.monotonic()
    try:
        _write(result, output_lock)
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    return connection


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def _nonnegative_number(value):
    try:
        return type(value) in (int, float) and value >= 0 and math.isfinite(value)
    except OverflowError:
        return False


def run(host, port, expected, timeout, workers, queue_size):
    """Serve request commands until stdin closes, then drain and exit."""
    host = "127.0.0.1" if host == "localhost" else host
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("host must be a loopback address")
    if type(port) is not int or not 1 <= port <= 65535 \
            or not _nonnegative_number(timeout) or not 0 < timeout <= 30 \
            or type(workers) is not int or not 1 <= workers <= 32 \
            or type(queue_size) is not int or not 1 <= queue_size <= 4096:
        raise ValueError("invalid client bounds")
    work = queue.Queue(maxsize=queue_size)
    output_lock = threading.Lock()
    failed = threading.Event()
    threads = []

    def worker():
        connection = None
        try:
            while True:
                item = work.get()
                try:
                    if item is None:
                        return
                    if not failed.is_set():
                        connection = _request(item, host, port, expected, timeout,
                                              output_lock, connection)
                except Exception:
                    failed.set()
                    if connection is not None:
                        connection.close()
                        connection = None
                finally:
                    work.task_done()
        finally:
            if connection is not None:
                connection.close()

    for _ in range(workers):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        threads.append(thread)

    try:
        _write({"type": "ready", "protocol": PROTOCOL_VERSION}, output_lock)
        while True:
            raw = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            if failed.is_set():
                return 2
            if len(raw) > MAX_LINE_BYTES:
                _write({"type": "protocol_error", "error": "line_too_large"}, output_lock)
                return 2
            try:
                command = json.loads(raw, object_pairs_hook=_unique_object)
            except (TypeError, ValueError, RecursionError):
                _write({"type": "protocol_error", "error": "invalid_json"}, output_lock)
                return 2
            if not isinstance(command, dict) or set(command) != {"type", "id", "scheduled_at"} \
                    or command["type"] != "request" or type(command["id"]) is not int \
                    or command["id"] < 0 or not _nonnegative_number(command["scheduled_at"]):
                _write({"type": "protocol_error", "error": "invalid_request"}, output_lock)
                return 2
            try:
                work.put_nowait(command)
            except queue.Full:
                now = time.monotonic()
                _write({"type": "result", "id": command["id"],
                         "scheduled_at": command["scheduled_at"],
                         "started_at": now, "ended_at": now,
                         "status": None, "ok": False,
                         "error": "client_queue_full", "http_version": None,
                         "connection_reused": False}, output_lock)
    except BrokenPipeError:
        return 2
    finally:
        work.join()
        for _ in threads:
            work.put(None)
        work.join()
        for thread in threads:
            thread.join()
    return 2 if failed.is_set() else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--queue-size", type=int, default=512)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 30 \
            or not 1 <= args.workers <= 32 or not 1 <= args.queue_size <= 4096:
        parser.error("invalid client bounds")
    try:
        return run(args.host, args.port, args.expected.encode(), args.timeout,
                   args.workers, args.queue_size)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
