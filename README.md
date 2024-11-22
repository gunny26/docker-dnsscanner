# DNS Query Sniffer in container

This container will sniff for DNS Request and export these
requests for prometheus as metrics.

requirement:
- Container must be run in privileged mode to get raw network data
- Container should run the local dns server or on a network where every traffice could be seen
