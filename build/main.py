#!/usr/bin/python3
import logging
import os
import sys
from prometheus_client import start_http_server, Counter

# import scapy
import scapy.all as scapy

logging.basicConfig(level=logging.INFO)

EXPORTER_LOG_LEVEL = os.environ.get("EXPORTER_LOG_LEVEL", "INFO")
EXPORTER_INTERFACE = os.environ.get(
    "EXPORTER_INTERFACE",
    "wlp4s0",  # default for development
)  # None to listen on all available, if set only this one
EXPORTER_DISPLAY_INTERVAL = int(os.environ.get("EXPORTER_DISPLAY_INTERVAL", "60"))
EXPORTER_PORT = int(os.environ.get("EXPORTER_PORT", "9100"))

logging.info("showing enviroment variables")
for key, value in os.environ.items():
    if key.startswith("EXPORTER_"):
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
    1: "A",  # 1 a host address
    2: "NS",  # 2 an authoritative name server
    3: "MD",  # 3 a mail destination (Obsolete - use MX)
    4: "MF",  # 4 a mail forwarder (Obsolete - use MX)
    5: "CNAME",  # 5 the canonical name for an alias
    6: "SOA",  # 6 marks the start of a zone of authority
    7: "MB",  # 7 a mailbox domain name (EXPERIMENTAL)
    8: "MG",  # 8 a mail group member (EXPERIMENTAL)
    9: "MR",  # 9 a mail rename domain name (EXPERIMENTAL)
    10: "NULL",  # 10 a null RR (EXPERIMENTAL)
    11: "WKS",  # 11 a well known service description
    12: "PTR",  # 12 a domain name pointer
    13: "HINFO",  # 13 host information
    14: "MINFO",  # 14 mailbox or mail list information
    15: "MX",  # 15 mail exchange
    16: "TXT",  # 16 text strings
    28: "AAAA",  # 28 a host address IPv6
    65: "HTTPS",  # 65 https address
    252: "AXFR",  # 252 A request for a transfer of an entire zone
    253: "MAILB",  # 253 A request for mailbox-related records (MB, MG or MR)
    254: "MAILA",  # 254 A request for mail agent RRs (Obsolete - see MX)
    255: "*",  # 255 A request for all records
}
QCLASS_MAP = {
    1: "IN",  # 1 the Internet
    2: "CS",  # 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    3: "CH",  # 3 the CHAOS class
    4: "HS",  # 4 Hesiod [Dyer 87]
    255: "*",  # 255 any class
}


class PacketHandler(object):
    """called if packet received"""

    def __init__(self):
        logging.info("PacketHandler initialized")

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

        if scapy.DNS in pkt and pkt[scapy.DNS].qr == 0:  # das qr bit 0 bedeutet anfrage
            # Extrahiere relevante Informationen aus dem DNS-Paket

            qname = pkt[scapy.DNS].qd.qname.decode("utf-8")
            qtype = (QTYPES_MAP.get(pkt[scapy.DNS].qd.qtype, "unknown"),)
            qclass = QCLASS_MAP.get(pkt[scapy.DNS].qd.qclass, "unknown")

            if qtype == "unknown" or qclass == "unknown":
                logging.debug(pkt.summary())
                logging.debug(pkt.show())

            logging.info(f"Query from {pkt[scapy.IP].src} to {pkt[scapy.IP].dst}:")
            logging.info(f"  Name: {qname}")
            logging.info(f"  Type: {pkt[scapy.DNS].qd.qtype} {qtype}")
            logging.info(f" Class: {pkt[scapy.DNS].qd.qclass} {qclass}")

            DNS_QUERY_TOTAL.labels(
                qname=pkt[scapy.DNS].qd.qname.decode("utf-8"),
                qtype=QTYPES_MAP.get(pkt[scapy.DNS].qd.qtype, "unknown"),
                qclass=QCLASS_MAP.get(pkt[scapy.DNS].qd.qclass, "unknown"),
            ).inc()


def main():
    # blocking main, this should not end
    packet_handler = PacketHandler()
    logging.info("Starting scan, showing all available interfaces")
    logging.info(scapy.get_if_list())
    if EXPORTER_INTERFACE not in scapy.get_if_list():
        logging.error(f"selected interface {EXPORTER_INTERFACE} is not available")
        sys.exit(1)
    with packet_handler as ph:
        # sniff(iface=iface, prn=ph.handle_packet, filter="arp",
        # store=False)
        # sniff(iface=iface, prn=ph.handle_packet, store=False)
        if EXPORTER_INTERFACE:
            scapy.sniff(
                filter="udp and port 53",
                iface=EXPORTER_INTERFACE,
                prn=ph.handle_packet,
                store=False,
            )
        else:
            scapy.sniff(prn=ph.handle_packet, store=False)


if __name__ == "__main__":
    if EXPORTER_LOG_LEVEL == "DEBUG":
        logging.getLogger().setLevel(logging.DEBUG)
    elif EXPORTER_LOG_LEVEL == "INFO":
        logging.getLogger().setLevel(logging.INFO)
    elif EXPORTER_LOG_LEVEL == "ERROR":
        logging.getLogger().setLevel(logging.ERROR)

    logging.info(f"starting prometheus exporter on port {EXPORTER_PORT}/tcp")
    start_http_server(EXPORTER_PORT)  # start prometheus exporter on selected port

    main()  # blocking           asyncio.run(main())
