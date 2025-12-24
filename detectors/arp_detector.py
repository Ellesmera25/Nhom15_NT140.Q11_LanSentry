from scapy.all import ARP, Ether
from logger_setup import alert
from config import TRUSTED_GATEWAYS
from state import StateStore

state = StateStore()


def arp_packet_cb(pkt):
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    ip = arp.psrc
    mac = arp.hwsrc

    if arp.psrc == arp.pdst:
        alert("warning", f"Gratuitous ARP from {mac} claiming {ip}")

    changed, old = state.update_arp(ip, mac)
    if changed:
        if ip in TRUSTED_GATEWAYS and TRUSTED_GATEWAYS[ip].lower() != mac.lower():
            alert("warning", f"ARP spoofing on gateway {ip}")
        else:
            alert("warning", f"ARP conflict {ip}: {old} → {mac}")

    if arp.op == 2 and pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
        alert("warning", f"Unsolicited ARP reply from {mac}")
