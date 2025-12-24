from scapy.all import sniff
from detectors.arp_detector import arp_packet_cb
from detectors.dhcp_detector import dhcp_packet_cb
from detectors.wifi_detector import wifi_packet_cb


def start_arp(iface):
    sniff(iface=iface, filter="arp", prn=arp_packet_cb, store=False)


def start_dhcp(iface):
    sniff(iface=iface, filter="udp and (port 67 or 68)", prn=dhcp_packet_cb, store=False)


def start_wifi(iface):
    sniff(iface=iface, prn=wifi_packet_cb, store=False)
