"""Send small, signed review announcements on the local IPv4 network."""

import socket
import threading
import time


class Announcements:
    NAMESPACE = "neighbor-review-lan-v1"
    PORT = 47821
    MAX_PACKET = 1200
    INTERVAL = 8

    def __init__(self, outgoing, receive):
        self.outgoing = outgoing
        self.receive = receive
        self.error = ""
        self.stopped = threading.Event()
        self.changed = threading.Event()
        self.thread = threading.Thread(target=self.listen, name="review-announcements", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)

    def wake(self):
        self.changed.set()

    def listen(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                connection.settimeout(0.5)
                connection.bind(("", self.PORT))
                next_send = 0
                while not self.stopped.is_set():
                    now = time.monotonic()
                    if self.changed.is_set() or now >= next_send:
                        self.changed.clear()
                        next_send = now + self.INTERVAL
                        try:
                            for packet in self.outgoing():
                                connection.sendto(packet, ("255.255.255.255", self.PORT))
                            self.error = ""
                        except (OSError, RuntimeError) as error:
                            self.error = str(error)
                    try:
                        packet, _ = connection.recvfrom(self.MAX_PACKET + 1)
                    except socket.timeout:
                        continue
                    if len(packet) <= self.MAX_PACKET:
                        self.receive(packet)
        except OSError as error:
            self.error = str(error)
