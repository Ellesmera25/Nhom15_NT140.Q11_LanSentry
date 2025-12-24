from scapy.all import BOOTP, DHCP, IP, Ether
from logger_setup import alert
from config import (
    TRUSTED_DHCP_SERVERS,
    TRUSTED_DNS,
    TRUSTED_GATEWAYS,
    DHCP_OFFER_MULTIPLE_SERVERS_THRESHOLD,
)
from state import StateStore

state = StateStore()


def dhcp_packet_cb(pkt):
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
        return

    bootp = pkt[BOOTP]
    options = dict(
        opt for opt in pkt[DHCP].options if isinstance(opt, tuple)
    )

    msg_type = options.get("message-type")
    client = bootp.chaddr[:6].hex()

    server_ip = options.get("server_id") or pkt[IP].src
    server_mac = pkt[Ether].src

    if msg_type in (2, 5):
        count = state.add_dhcp_offer(client, server_ip, server_mac)
        if count > DHCP_OFFER_MULTIPLE_SERVERS_THRESHOLD:
            alert("warning", f"Multiple DHCP servers: {server_ip}")

        router = options.get("router")
        if router and str(router) not in TRUSTED_GATEWAYS:
            alert("warning", f"Rogue DHCP gateway {router}")
