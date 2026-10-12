#!/usr/bin/env python3
"""Bounded selector-driven loopback HTTP/1.1 capacity client (stdlib only).

One socket per active request; no worker queue, request threads, or retries.
Stdin/stdout are bounded nonblocking JSON-line streams. EOF drains requests;
protocol/resource failures terminate the instrument with exit status 2.
"""

import argparse
from collections import deque
import errno
import ipaddress
import json
import math
import os
import re
import resource
import selectors
import signal
import socket
import sys
import time


IMPLEMENTATION = "bounded-nonblocking-http11-v1"
MAX_INFLIGHT = 4096
MAX_IDLE_CONNECTIONS = 32
MIN_NOFILE = 8192
MAX_LINE_BYTES = 4096
MAX_BODY_BYTES = 4096
MAX_HEADER_BYTES = 16384
MAX_WIRE_BYTES = 65536
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
PROTOCOL_VERSION = 1
_RESOURCE_ERRORS = {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOBUFS,
                    errno.EADDRNOTAVAIL, errno.EADDRINUSE, errno.EAGAIN,
                    errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT,
                    errno.EPROTONOSUPPORT}
_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class _ProtocolFailure(Exception):
    pass


class _BadResponse(Exception):
    pass


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError("nonfinite number")


def _nonnegative_number(value):
    try:
        return type(value) in (int, float) and value >= 0 and math.isfinite(value)
    except OverflowError:
        return False


def ensure_descriptor_limit():
    """Raise only this instrument process's soft limit; never change the hard limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < MIN_NOFILE:
        raise _ProtocolFailure("descriptor_limit_too_low")
    if soft != resource.RLIM_INFINITY and soft < MIN_NOFILE:
        resource.setrlimit(resource.RLIMIT_NOFILE, (MIN_NOFILE, hard))


def _command(raw):
    if len(raw) > MAX_LINE_BYTES:
        raise _ProtocolFailure("line_too_large")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (TypeError, ValueError, RecursionError):
        raise _ProtocolFailure("invalid_json") from None
    if type(value) is not dict or set(value) != {"type", "id", "scheduled_at"} \
            or value["type"] != "request" or type(value["id"]) is not int \
            or value["id"] < 0 or not _nonnegative_number(value["scheduled_at"]):
        raise _ProtocolFailure("invalid_request")
    return value


def _result(command):
    now = time.monotonic()
    return {"type": "result", "id": command["id"],
            "scheduled_at": command["scheduled_at"], "started_at": now,
            "ended_at": None, "status": None, "ok": False, "error": None,
            "http_version": None, "connection_reused": False}


def _fields(lines):
    fields = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator or not _TOKEN.fullmatch(name) \
                or any(c < 32 and c != 9 or c == 127 for c in value):
            raise _BadResponse
        fields.setdefault(name.lower(), []).append(value.strip(b" \t"))
    return fields


class _Response:
    """Incremental strict framing, with independent payload and wire bounds."""

    def __init__(self):
        self.buffer = bytearray()
        self.body = bytearray()
        self.wire_bytes = 0
        self.state = "headers"
        self.status = self.version = None
        self.remaining = 0
        self.keepalive = False
        self.informational = 0

    def _headers(self, block):
        lines = block.split(b"\r\n")
        match = re.fullmatch(rb"HTTP/1\.([01]) ([1-5][0-9]{2})[ \t]([^\r\n]*)", lines[0])
        if not match or any(c < 32 and c != 9 or c == 127 for c in match[3]):
            raise _BadResponse
        version, status = 10 + int(match[1]), int(match[2])
        fields = _fields(lines[1:])
        lengths = fields.get(b"content-length", [])
        transfer = fields.get(b"transfer-encoding", [])
        if len(lengths) > 1 or len(transfer) > 1 or lengths and transfer:
            raise _BadResponse
        if lengths and not re.fullmatch(rb"[0-9]{1,10}", lengths[0]):
            raise _BadResponse
        if transfer and transfer[0].lower() != b"chunked":
            raise _BadResponse
        if status < 200:
            self.informational += 1
            if status == 101 or lengths or transfer or self.informational > 8:
                raise _BadResponse
            return
        self.version, self.status = version, status
        tokens = [item.strip().lower() for value in fields.get(b"connection", [])
                  for item in value.split(b",")]
        if any(not _TOKEN.fullmatch(item) for item in tokens):
            raise _BadResponse
        self.keepalive = version == 11 and b"close" not in tokens
        if status in (204, 304):
            if transfer or status == 204 and lengths and int(lengths[0]) != 0:
                raise _BadResponse
            self.state = "done"
        elif transfer:
            self.state = "chunk_size"
        elif lengths:
            self.remaining = int(lengths[0])
            if self.remaining > MAX_BODY_BYTES:
                raise _BadResponse
            self.state = "fixed" if self.remaining else "done"
        else:
            # Only an explicitly closing connection can delimit an HTTP/1.1 body.
            if self.keepalive:
                raise _BadResponse
            self.state = "eof_body"

    def feed(self, data):
        self.wire_bytes += len(data)
        if self.wire_bytes > MAX_WIRE_BYTES:
            raise _BadResponse
        self.buffer.extend(data)
        while True:
            if self.state == "headers":
                end = self.buffer.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.buffer) > MAX_HEADER_BYTES:
                        raise _BadResponse
                    return False
                if end + 4 > MAX_HEADER_BYTES:
                    raise _BadResponse
                block = bytes(self.buffer[:end])
                del self.buffer[:end + 4]
                self._headers(block)
            elif self.state in ("fixed", "chunk_data"):
                count = min(self.remaining, len(self.buffer))
                self.body.extend(self.buffer[:count])
                del self.buffer[:count]
                self.remaining -= count
                if self.remaining:
                    return False
                self.state = "done" if self.state == "fixed" else "chunk_end"
            elif self.state == "chunk_size":
                end = self.buffer.find(b"\r\n")
                if end < 0:
                    if len(self.buffer) > 1024:
                        raise _BadResponse
                    return False
                line = bytes(self.buffer[:end])
                del self.buffer[:end + 2]
                # Extensions use token or quoted-string values; no bare controls.
                token = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
                quoted = rb'"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*"'
                grammar = rb"([0-9A-Fa-f]{1,16})(?:[ \t]*;[ \t]*" + token \
                    + rb"(?:[ \t]*=[ \t]*(?:" + token + b"|" + quoted + rb"))?)*[ \t]*"
                match = re.fullmatch(grammar, line)
                if end > 1024 or not match:
                    raise _BadResponse
                self.remaining = int(match[1], 16)
                if len(self.body) + self.remaining > MAX_BODY_BYTES:
                    raise _BadResponse
                self.state = "chunk_data" if self.remaining else "trailers"
            elif self.state == "chunk_end":
                if len(self.buffer) < 2:
                    return False
                if self.buffer[:2] != b"\r\n":
                    raise _BadResponse
                del self.buffer[:2]
                self.state = "chunk_size"
            elif self.state == "trailers":
                if self.buffer[:2] == b"\r\n":
                    del self.buffer[:2]
                    self.state = "done"
                    continue
                end = self.buffer.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.buffer) > MAX_HEADER_BYTES:
                        raise _BadResponse
                    return False
                if end + 4 > MAX_HEADER_BYTES:
                    raise _BadResponse
                fields = _fields(bytes(self.buffer[:end]).split(b"\r\n"))
                if set(fields) & {b"content-length", b"transfer-encoding", b"connection",
                                  b"host", b"trailer"}:
                    raise _BadResponse
                del self.buffer[:end + 4]
                self.state = "done"
            elif self.state == "eof_body":
                if len(self.body) + len(self.buffer) > MAX_BODY_BYTES:
                    raise _BadResponse
                self.body.extend(self.buffer)
                self.buffer.clear()
                return False
            else:
                if self.buffer:
                    raise _BadResponse
                return True

    def eof(self):
        if self.state != "eof_body":
            raise _BadResponse
        self.state = "done"
        self.keepalive = False


class _Request:
    def __init__(self, result, timeout):
        self.result = result
        self.deadline = result["started_at"] + timeout
        self.state = "connect"
        self.sent = 0
        self.response = _Response()


class _Client:
    def __init__(self, host, port, expected, timeout, max_outstanding, max_idle):
        address = ipaddress.ip_address(host)
        self.family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        self.address = (host, port, 0, 0) if address.version == 6 else (host, port)
        authority = "[{}]".format(host) if address.version == 6 else host
        self.get = ("GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n\r\n"
                    .format(authority, port)).encode("ascii")
        self.expected, self.timeout = expected, timeout
        self.max_outstanding, self.max_idle = max_outstanding, max_idle
        self.selector = selectors.DefaultSelector()
        self.active = {}  # Insertion order also orders identical-budget deadlines.
        self.idle = {}  # Owned sockets registered for unexpected data/EOF.
        self.input = bytearray()
        self.output = deque()
        self.output_bytes = 0
        self.stdin = sys.stdin.fileno()
        self.stdout = sys.stdout.fileno()
        self.input_eof = False
        self.input_registered = False
        self.output_registered = False
        self.input_regular = self.output_regular = False
        self.fatal = False
        self.exit_code = 0
        self.stop_deadline = None
        self.interrupted = False
        self.output_progress = time.monotonic()

    def unregister(self, item):
        try:
            self.selector.unregister(item)
        except KeyError:
            pass

    def close_socket(self, sock):
        self.unregister(sock)
        self.active.pop(sock, None)
        self.idle.pop(sock, None)
        sock.close()

    def emit(self, record):
        data = (json.dumps(record, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(data) > MAX_LINE_BYTES:
            raise _ProtocolFailure("output_record_too_large")
        if self.output_bytes + len(data) > MAX_OUTPUT_BYTES:
            raise _ProtocolFailure("output_buffer_full")
        if not self.output:
            self.output_progress = time.monotonic()
        self.output.append(data)
        self.output_bytes += len(data)
        if not self.output_registered and not self.output_regular:
            try:
                self.selector.register(self.stdout, selectors.EVENT_WRITE, "stdout")
                self.output_registered = True
            except PermissionError:
                self.output_regular = True
            except OSError:
                raise _ProtocolFailure("output_failure") from None

    def fail(self, error):
        self.fatal = True
        self.exit_code = 2
        self.input_eof = True
        self.input.clear()
        self.unregister(self.stdin)
        self.input_registered = False
        for sock in list(self.active) + list(self.idle):
            self.close_socket(sock)
        self.stop_deadline = time.monotonic() + 1.0
        self.emit({"type": "protocol_error", "error": error})

    def start(self, command):
        result = _result(command)  # Actual processing time, before any socket operation.
        if len(self.active) >= self.max_outstanding:
            result.update(ended_at=time.monotonic(), error="client_queue_full")
            self.emit(result)
            self.fail("client_queue_full")
            return
        request = _Request(result, self.timeout)
        sock = None
        while self.idle and time.monotonic() < request.deadline:
            candidate = next(iter(self.idle))
            try:
                data = candidate.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                sock = candidate
                self.idle.pop(sock)
                result["connection_reused"] = True
                request.state = "send"
                break
            except OSError as error:
                if error.errno in _RESOURCE_ERRORS:
                    raise _ProtocolFailure("client_resource_error") from None
            # EOF or unexpected bytes: discard before sending, never replay a GET.
            self.close_socket(candidate)
        if time.monotonic() >= request.deadline:
            if sock is not None:
                self.close_socket(sock)
            result.update(ended_at=time.monotonic(), error="timeout")
            self.emit(result)
            return
        try:
            if sock is None:
                sock = socket.socket(self.family, socket.SOCK_STREAM)
                self.active[sock] = request
                sock.setblocking(False)
                code = sock.connect_ex(self.address)
                if code == 0:
                    request.state = "send"
                elif code not in (errno.EINPROGRESS, errno.EWOULDBLOCK,
                                   errno.EALREADY, errno.EINTR):
                    raise OSError(code, "connect")
            else:
                self.active[sock] = request
        except OSError as error:
            if sock is not None:
                self.close_socket(sock)
            if error.errno in _RESOURCE_ERRORS:
                raise _ProtocolFailure("client_resource_error") from None
            now = time.monotonic()
            result.update(ended_at=now,
                          error="timeout" if now >= request.deadline else "transport_error")
            self.emit(result)
            return
        try:
            if result["connection_reused"]:
                self.selector.modify(sock, selectors.EVENT_WRITE, request)
            else:
                self.selector.register(sock, selectors.EVENT_WRITE, request)
        except OSError:
            raise _ProtocolFailure("client_resource_error") from None

    def finish(self, sock, error=None):
        request = self.active[sock]
        response, result = request.response, request.result
        result["status"], result["http_version"] = response.status, response.version
        reusable = False
        if time.monotonic() >= request.deadline:
            error = "timeout"
        if error is None:
            if response.version != 11:
                error = "unexpected_http_version"
            elif response.body != self.expected:
                error = "unexpected_response"
            elif response.status != 200:
                error = "http_status"
            else:
                result["ok"] = True
                reusable = response.keepalive
        result.update(error=error, ended_at=time.monotonic())
        self.active.pop(sock)
        # Keep ownership until output is queued, so fatal write failures close it.
        self.idle[sock] = None
        self.emit(result)
        if reusable and len(self.idle) <= self.max_idle:
            try:
                self.selector.modify(sock, selectors.EVENT_READ, "idle")
            except OSError:
                raise _ProtocolFailure("client_resource_error") from None
        else:
            self.close_socket(sock)

    def service(self, sock):
        request = self.active.get(sock)
        if request is None:
            return
        if time.monotonic() >= request.deadline:
            self.finish(sock, "timeout")
            return
        try:
            if request.state == "connect":
                code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code:
                    raise OSError(code, "connect")
                request.state = "send"
            if request.state == "send":
                count = sock.send(self.get[request.sent:])
                if not count:
                    raise _BadResponse
                request.sent += count
                if request.sent == len(self.get):
                    request.state = "read"
                    try:
                        self.selector.modify(sock, selectors.EVENT_READ, request)
                    except OSError:
                        raise _ProtocolFailure("client_resource_error") from None
                return
            data = sock.recv(8192)
            if not data:
                request.response.eof()
                self.finish(sock)
            elif request.response.feed(data):
                self.finish(sock)
        except BlockingIOError:
            pass
        except _BadResponse:
            self.finish(sock, "transport_error")
        except OSError as error:
            if error.errno in _RESOURCE_ERRORS:
                raise _ProtocolFailure("client_resource_error") from None
            self.finish(sock, "transport_error")

    def read_input(self):
        if not self.input_eof and b"\n" not in self.input:
            try:
                data = os.read(self.stdin, MAX_LINE_BYTES + 1 - len(self.input))
            except BlockingIOError:
                data = None
            if data == b"":
                self.input_eof = True
                self.unregister(self.stdin)
                self.input_registered = False
            elif data:
                self.input.extend(data)
        for _ in range(64):
            end = self.input.find(b"\n")
            if end < 0:
                if len(self.input) > MAX_LINE_BYTES:
                    raise _ProtocolFailure("line_too_large")
                if not self.input_eof or not self.input:
                    return
                raw = bytes(self.input)
                self.input.clear()
            else:
                raw = bytes(self.input[:end + 1])
                del self.input[:end + 1]
            self.start(_command(raw))
            if self.fatal:
                return

    def flush_output(self):
        budget = 65536
        while self.output and budget > 0:
            chunk = self.output[0]
            try:
                count = os.write(self.stdout, chunk[:budget])
            except BlockingIOError:
                return
            if count <= 0:
                raise _ProtocolFailure("output_failure")
            budget -= count
            self.output_bytes -= count
            self.output_progress = time.monotonic()
            if count == len(chunk):
                self.output.popleft()
            else:
                self.output[0] = chunk[count:]
        if not self.output and self.output_registered:
            self.unregister(self.stdout)
            self.output_registered = False

    def interrupt(self, signum, frame):
        self.interrupted = True

    def serve(self):
        old_blocking = {}
        old_signals = {}
        try:
            for fd in (self.stdin, self.stdout):
                old_blocking[fd] = os.get_blocking(fd)
                os.set_blocking(fd, False)
            for signum in (signal.SIGTERM, signal.SIGINT):
                old_signals[signum] = signal.signal(signum, self.interrupt)
            try:
                self.selector.register(self.stdin, selectors.EVENT_READ, "stdin")
                self.input_registered = True
            except PermissionError:
                self.input_regular = True
            self.emit({"type": "ready", "protocol": PROTOCOL_VERSION})
            while True:
                try:
                    if self.interrupted and not self.fatal:
                        self.fail("interrupted")
                    now = time.monotonic()
                    if self.stop_deadline is not None and now >= self.stop_deadline:
                        return 2
                    if self.output and now - self.output_progress >= self.timeout:
                        if self.fatal:
                            return 2
                        raise _ProtocolFailure("output_stalled")
                    while self.active:
                        sock = next(iter(self.active))
                        if self.active[sock].deadline > now:
                            break
                        self.finish(sock, "timeout")
                    if not self.fatal and (b"\n" in self.input or self.input_regular
                                           or self.input_eof and self.input):
                        self.read_input()
                    if self.input_eof:
                        for sock in list(self.idle):
                            self.close_socket(sock)
                    if self.output_regular:
                        self.flush_output()
                    if self.input_eof and not self.input and not self.active and not self.output:
                        return self.exit_code
                    delay = 0.25
                    if self.active:
                        delay = min(delay, max(0, next(iter(self.active.values())).deadline
                                               - time.monotonic()))
                    if not self.fatal and (self.input_regular and not self.input_eof
                                           or b"\n" in self.input):
                        delay = 0
                    for key, mask in self.selector.select(delay):
                        if key.data == "stdout":
                            self.flush_output()
                        elif self.fatal:
                            continue
                        elif key.data == "stdin":
                            self.read_input()
                        elif key.data == "idle":
                            # Idle readability is either EOF or unsolicited bytes.
                            if key.fileobj in self.idle:
                                self.close_socket(key.fileobj)
                        else:
                            self.service(key.fileobj)
                except _ProtocolFailure as error:
                    if self.fatal:
                        return 2
                    self.input.clear()
                    self.fail(str(error))
                except (OSError, ValueError, MemoryError):
                    # Includes pipe, selector, local memory and descriptor errors.
                    # These are terminal instrument failures, not HTTP outcomes.
                    return 2
        finally:
            for sock in list(self.active) + list(self.idle):
                self.close_socket(sock)
            self.selector.close()
            for signum, handler in old_signals.items():
                signal.signal(signum, handler)
            for fd, blocking in old_blocking.items():
                try:
                    os.set_blocking(fd, blocking)
                except OSError:
                    pass


def run(host, port, expected_bytes, timeout=30, max_outstanding=MAX_INFLIGHT,
        max_idle=MAX_IDLE_CONNECTIONS):
    """Read stdin commands, write protocol-v1 results; return 0 or terminal 2.

    Invalid configuration raises ValueError. Request operations have a single
    monotonic deadline. Output stalls and signal shutdown are also bounded.
    """
    host = "127.0.0.1" if host == "localhost" else host
    try:
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError):
        raise ValueError("host must be a numeric loopback address or localhost") from None
    if type(host) is not str or not address.is_loopback or "%" in host:
        raise ValueError("host must be a numeric loopback address or localhost")
    if type(port) is not int or not 1 <= port <= 65535 \
            or not _nonnegative_number(timeout) or not 0 < timeout <= 30 \
            or type(max_outstanding) is not int or not 1 <= max_outstanding <= MAX_INFLIGHT \
            or type(max_idle) is not int or not 0 <= max_idle <= MAX_IDLE_CONNECTIONS \
            or type(expected_bytes) is not bytes or len(expected_bytes) > MAX_BODY_BYTES:
        raise ValueError("invalid client bounds")
    try:
        ensure_descriptor_limit()
        client = _Client(str(address), port, expected_bytes, timeout, max_outstanding, max_idle)
        return client.serve()
    except (OSError, MemoryError, _ProtocolFailure):
        return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-outstanding", type=int, default=MAX_INFLIGHT)
    parser.add_argument("--max-idle", type=int, default=MAX_IDLE_CONNECTIONS)
    args = parser.parse_args(argv)
    try:
        return run(args.host, args.port, args.expected.encode(), args.timeout,
                   args.max_outstanding, args.max_idle)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
