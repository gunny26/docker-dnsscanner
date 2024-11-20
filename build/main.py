#!/usr/bin/python3
import logging
import os
import sys
import time
from prometheus_client import start_http_server, Counter

# import scapy
import scapy.all as scapy

logging.basicConfig(level=logging.INFO)

APP_LOG_LEVEL = os.environ.get("APP_LOG_LEVEL", "INFO")
APP_INTERFACE = os.environ.get(
    "APP_INTERFACE",
    "wlp4s0",  # default for development
)  # None to listen on all available, if set only this one
APP_DISPLAY_INTERVAL = int(os.environ.get("APP_DISPLAY_INTERVAL", "60"))
APP_PORT = int(os.environ.get("APP_PORT", "9100"))

logging.info("showing enviroment variables")
for key, value in os.environ.items():
    if key.startswith("APP_"):
        logging.info(f"{key}: {value}")

# prometheus metrics
MAC_SEEN_TOTAL = Counter(
    "netscanner_mac_seen_total",
    "Number of intervals this MAC address was seen",
    [
        "address",
    ],
)
IPV4_SEEN_TOTAL = Counter(
    "netscanner_ipv4_seen_total",
    "Number of intervals this ipv4 address was seen",
    [
        "address",
    ],
)
IPV6_SEEN_TOTAL = Counter(
    "netscanner_ipv6_seen_total",
    "Number of intervals this ipv6 address was seen",
    [
        "address",
    ],
)

BLACKLIST = [
    "ff:ff:ff:ff:ff:ff",
]  # list of blacklisted macs


class Harvester:
    """used by packet handler and collecting information"""

    def __init__(self, prom_counter, label):
        """
        tableid one of mac, ip, ipv6
        label human readable tablename just for display
        """
        self.prom_counter = prom_counter
        self.label = label  # just for display
        self.data = {}  # local dict storage

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass

    def add(self, key, values=None):
        """
        method called by Packethandler
        key could be mac, ipv4 or ipv6
        """
        self.prom_counter.labels(address=key).inc()
        if key not in self.data:  # internal data, just for debug and display
            self.data[key] = {
                "address": key,
                "first_seen": time.time(),
                "last_seen": 0,
                "seen": 0,
            }
        self.data[key]["seen"] += 1
        self.data[key]["last_seen"] = time.time()


class PacketHandler(object):
    """called if packet received"""

    def __init__(self):
        print("paket handler started")

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass

    def handle_packet(self, pkt):
        # method called if packet arrives
        # print(pkt.layers())  # show layers
        # print(pkt.summary())  # oneline summary
        # print(pkt.show())  # data structure
        # print(pkt.src)

        if pkt.dst.startswith("33:33:") or pkt.dst.startswith(
            "01:00:5e:"
        ):  # multicast ipv6 and ipv4
            return

        if (pkt.src in BLACKLIST) or (pkt.dst in BLACKLIST):  # skip if blacklisted
            return

        if scapy.DNS in pkt:
            # Extrahiere relevante Informationen aus dem DNS-Paket
            print(pkt.summary())

        # mac addresses update - thats always available
        # mac_harvester.add(str(pkt.src))
        # mac_harvester.add(str(pkt.dst))

        # ipv4 update
        #ip = pkt.getlayer("IP")
        #if ip:
        #    # print(ip.summary())
        #    ipv4_harvester.add(str(ip.src))
        #    ipv4_harvester.add(str(ip.dst))

        # ipv6 update
        #ip6 = pkt.getlayer("ipv6")
        #if ip6:
        #    # print(ip6.summary())
        #    ipv6_harvester.add(str(ip6.src))
        #    ipv6_harvester.add(str(ip6.dst))


def main():
    # blocking main, this should not end
    packet_handler = PacketHandler()
    logging.info("Starting scan, showing all available interfaces")
    logging.info(scapy.get_if_list())
    if APP_INTERFACE not in scapy.get_if_list():
        logging.error(f"selected interface {APP_INTERFACE} is not available")
        sys.exit(1)
    with packet_handler as ph:
        # sniff(iface=iface, prn=ph.handle_packet, filter="arp",
        # store=False)
        # sniff(iface=iface, prn=ph.handle_packet, store=False)
        if APP_INTERFACE:
            scapy.sniff(
                filter="udp and port 53",
                iface=APP_INTERFACE,
                prn=ph.handle_packet,
                store=False,
            )
        else:
            scapy.sniff(prn=ph.handle_packet, store=False)


if __name__ == "__main__":
    if APP_LOG_LEVEL == "DEBUG":
        logging.getLogger().setLevel(logging.DEBUG)
    elif APP_LOG_LEVEL == "INFO":
        logging.getLogger().setLevel(logging.INFO)
    elif APP_LOG_LEVEL == "ERROR":
        logging.getLogger().setLevel(logging.ERROR)

    logging.info(f"starting prometheus exporter on port {APP_PORT}/tcp")
    start_http_server(APP_PORT)  # start prometheus exporter on selected port

    # collecting mac, ipv4 and ipv6 addresses
    mac_harvester = Harvester(prom_counter=MAC_SEEN_TOTAL, label="mac addresses")
    ipv4_harvester = Harvester(prom_counter=IPV4_SEEN_TOTAL, label="ipv4 addresses")
    ipv6_harvester = Harvester(prom_counter=IPV6_SEEN_TOTAL, label="ipv6 addresses")

    main()  # blocking           asyncio.run(main())
