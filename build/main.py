#!/usr/bin/python3
import logging
import os
import sys
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
DNS_QUERY_TOTAL = Counter(
    "dnsscanner_qname_total",
    "Number of queries for this dns record",
    [
        "qname",
        "qtype",
        "qclass",
    ],
)

BLACKLIST = [
    "ff:ff:ff:ff:ff:ff",
]  # list of blacklisted macs

# taken from RF1035
QTYPES_MAP = {
    1: "A",         # 1 a host address
    2: "NS",        # 2 an authoritative name server
    3: "MD",        # 3 a mail destination (Obsolete - use MX)
    4: "MF",        # 4 a mail forwarder (Obsolete - use MX)
    5: "CNAME",     # 5 the canonical name for an alias
    6: "SOA",       # 6 marks the start of a zone of authority
    7: "MB",        # 7 a mailbox domain name (EXPERIMENTAL)
    8: "MG",        # 8 a mail group member (EXPERIMENTAL)
    9: "MR",        # 9 a mail rename domain name (EXPERIMENTAL)
    10: "NULL",     # 10 a null RR (EXPERIMENTAL)
    11: "WKS",      # 11 a well known service description
    12: "PTR",      # 12 a domain name pointer
    13: "HINFO",    # 13 host information
    14: "MINFO",    # 14 mailbox or mail list information
    15: "MX",       # 15 mail exchange
    16: "TXT",      # 16 text strings
    28: "AAAA",     # 28 a host address IPv6
    252: "AXFR",    # 252 A request for a transfer of an entire zone
    253: "MAILB",   # 253 A request for mailbox-related records (MB, MG or MR)
    254: "MAILA",   # 254 A request for mail agent RRs (Obsolete - see MX)
    255: "*",       # 255 A request for all records
}
QCLASS_MAP = {
    1: "IN",        # 1 the Internet
    2: "CS",        # 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    3: "CH",        # 3 the CHAOS class
    4: "HS",        # 4 Hesiod [Dyer 87]
    255: "*",       # 255 any class
}


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

        if scapy.DNS in pkt and pkt[scapy.DNS].qr == 0:  # das qr bit 0 bedeutet anfrage
            # Extrahiere relevante Informationen aus dem DNS-Paket
            print(pkt.summary())
            print(pkt.show())

            print(f"Query from {pkt[scapy.IP].src} to {pkt[scapy.IP].dst}:")
            print(f"  Name: {pkt[scapy.DNS].qd.qname.decode('utf-8')}")
            print(f"  Type: {pkt[scapy.DNS].qd.qtype}")
            print(f"  Type: {QTYPES_MAP.get(pkt[scapy.DNS].qd.qtype, 'unknown')}")
            print(f"  Type: {pkt[scapy.DNS].qd.qclass}")
            print(f"  Type: {QCLASS_MAP.get(pkt[scapy.DNS].qd.qclass, 'unknown')}")

            DNS_QUERY_TOTAL.labels(
                qname=pkt[scapy.DNS].qd.qname.decode('utf-8'),
                qtype=QTYPES_MAP.get(pkt[scapy.DNS].qd.qtype, "unknown"),
                qclass=QCLASS_MAP.get(pkt[scapy.DNS].qd.qclass, "unknown")
            ).inc()


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

    main()  # blocking           asyncio.run(main())
