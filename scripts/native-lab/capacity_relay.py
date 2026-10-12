#!/usr/bin/env python3
"""Bounded byte-transparent guest-loopback to fixture-loopback TCP relay."""

import argparse
import errno
import json
import os
import selectors
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
from guard import require_lab

MAX_CONNECTIONS = 32
BUFFER_BYTES = 65536
INACTIVITY_SECONDS = 30.0
# Also bound an orphan relay; the controlling agent has a shorter run deadline.
MAX_LIFETIME_SECONDS = 3240


class Bridge:
    def __init__(self, client, target_port):
        self.sockets = [client, socket.socket(socket.AF_INET, socket.SOCK_STREAM)]
        self.buffers = [bytearray(), bytearray()]
        self.eof = [False, False]
        self.shutdown = [False, False]
        self.connecting = True
        self.touched = time.monotonic()
        for stream in self.sockets:
            stream.setblocking(False)
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        result = self.sockets[1].connect_ex(("127.0.0.1", target_port))
        if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            self.close()
            raise OSError("fixture connection failed")
        self.connecting = result != 0

    def close(self):
        for stream in self.sockets:
            stream.close()

    def interests(self, side):
        if side == 1 and self.connecting:
            return selectors.EVENT_WRITE
        events = 0
        if not self.eof[side] and len(self.buffers[1 - side]) < BUFFER_BYTES:
            events |= selectors.EVENT_READ
        if self.buffers[side] and not (side == 1 and self.connecting):
            events |= selectors.EVENT_WRITE
        return events

    def transfer(self, side, events):
        stream = self.sockets[side]
        if side == 1 and self.connecting:
            if stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                raise OSError("fixture connection failed")
            self.connecting = False
        if events & selectors.EVENT_READ and not self.eof[side]:
            destination = self.buffers[1 - side]
            try:
                data = stream.recv(min(16384, BUFFER_BYTES - len(destination)))
            except BlockingIOError:
                data = None
            if data:
                destination.extend(data)
                self.touched = time.monotonic()
            elif data == b"":
                self.eof[side] = True
        if events & selectors.EVENT_WRITE and self.buffers[side]:
            try:
                count = stream.send(self.buffers[side])
            except BlockingIOError:
                count = 0
            if count:
                del self.buffers[side][:count]
                self.touched = time.monotonic()
        for index in (0, 1):
            if self.eof[1 - index] and not self.buffers[index] and not self.shutdown[index] \
                    and not (index == 1 and self.connecting):
                self.sockets[index].shutdown(socket.SHUT_WR)
                self.shutdown[index] = True
        return all(self.eof) and not any(self.buffers)


def run(listener, target_port):
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    previous = {number: signal.signal(number, stop)
                for number in (signal.SIGTERM, signal.SIGINT)}
    bridges = set()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + MAX_LIFETIME_SECONDS
    try:
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, None)
        print(json.dumps({"type": "ready", "protocol": 1, "pid": os.getpid(),
                          "port": listener.getsockname()[1], "target_port": target_port,
                          "max_connections": MAX_CONNECTIONS,
                          "inactivity_seconds": INACTIVITY_SECONDS}), flush=True)
        while not stopped and time.monotonic() < deadline:
            # Rebuild at most 65 registrations; each buffer has a hard bound.
            for key in list(selector.get_map().values()):
                if key.fileobj is not listener:
                    selector.unregister(key.fileobj)
            for bridge in tuple(bridges):
                if time.monotonic() - bridge.touched >= INACTIVITY_SECONDS:
                    bridge.close()
                    bridges.remove(bridge)
                    continue
                for side, stream in enumerate(bridge.sockets):
                    events = bridge.interests(side)
                    if events:
                        selector.register(stream, events, (bridge, side))
            for key, events in selector.select(0.25):
                if stopped:
                    break
                if key.fileobj is listener:
                    try:
                        client, address = listener.accept()
                    except BlockingIOError:
                        continue
                    if address[0] != "127.0.0.1" or len(bridges) >= MAX_CONNECTIONS:
                        client.close()
                        continue
                    try:
                        bridges.add(Bridge(client, target_port))
                    except OSError:
                        client.close()
                else:
                    bridge, side = key.data
                    if bridge not in bridges:
                        continue
                    try:
                        complete = bridge.transfer(side, events)
                    except OSError:
                        complete = True
                    if complete:
                        # Unregister before closing: a new accept may reuse FDs.
                        for stream in bridge.sockets:
                            try:
                                selector.unregister(stream)
                            except KeyError:
                                pass
                        bridge.close()
                        bridges.remove(bridge)
    finally:
        listener.close()
        for bridge in bridges:
            bridge.close()
        selector.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-fd", type=int, required=True)
    parser.add_argument("--target-port", type=int, required=True)
    args = parser.parse_args(argv)
    if args.listen_fd < 3 or args.target_port != 3000:
        parser.error("relay requires an inherited listener and the fixed fixture port")
    # No socket mutation or process creation before the disposable guest guard.
    if require_lab() != "qemu" or os.geteuid() != 0:
        raise SystemExit("relay requires the marked QEMU guest and root")
    listener = socket.socket(fileno=args.listen_fd)
    try:
        if listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM \
                or listener.getsockname()[0] != "127.0.0.1" \
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
            raise ValueError("relay requires an inherited IPv4 loopback TCP listener")
        run(listener, args.target_port)
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        # Never emit response bytes, environment values, or arbitrary exceptions.
        print("capacity relay failed", file=sys.stderr)
        raise SystemExit(1)
