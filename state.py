from collections import defaultdict
from datetime import datetime


class StateStore:
    def __init__(self):
        self.ip2mac = {}
        self.mac2ips = defaultdict(set)
        self.dhcp_offers = defaultdict(set)
        self.ap_seen = {}
        self.ap_fingerprint = {}

    def update_arp(self, ip, mac):
        old = self.ip2mac.get(ip)
        if old is None:
            self.ip2mac[ip] = mac
            self.mac2ips[mac].add(ip)
            return False, None

        if old.lower() != mac.lower():
            self.ip2mac[ip] = mac
            self.mac2ips[old].discard(ip)
            self.mac2ips[mac].add(ip)
            return True, old

        return False, None

    def add_dhcp_offer(self, client, server_ip, server_mac):
        self.dhcp_offers[client].add((server_ip, server_mac))
        return len(self.dhcp_offers[client])

    def update_ap(self, bssid, ssid):
        now = datetime.utcnow()
        self.ap_seen.setdefault(
            bssid, {"ssid": ssid, "first_seen": now}
        )["last_seen"] = now
