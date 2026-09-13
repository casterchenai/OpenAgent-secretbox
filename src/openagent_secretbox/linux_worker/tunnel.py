"""Bounded fixed-destination TCP relay. TLS stays end-to-end at the worker."""

from __future__ import annotations

import selectors
import signal
import socket
import threading
import time


def main() -> None:
    stopping = threading.Event()
    slots = threading.BoundedSemaphore(8)

    def relay(client: socket.socket) -> None:
        try:
            with client, socket.create_connection(("worker", 8443), timeout=3) as upstream:
                client.settimeout(1)
                upstream.settimeout(1)
                with selectors.DefaultSelector() as selector:
                    selector.register(client, selectors.EVENT_READ, upstream)
                    selector.register(upstream, selectors.EVENT_READ, client)
                    deadline = time.monotonic() + 15
                    while not stopping.is_set() and time.monotonic() < deadline:
                        for key, _ in selector.select(0.2):
                            source = key.fileobj
                            assert isinstance(source, socket.socket)
                            chunk = source.recv(16384)
                            if not chunk:
                                return
                            key.data.sendall(chunk)
        except OSError:
            pass
        finally:
            client.close()
            slots.release()

    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    with socket.create_server(("0.0.0.0", 8443), backlog=8) as listener:
        listener.settimeout(0.2)
        while not stopping.is_set():
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            if not slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=relay, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
