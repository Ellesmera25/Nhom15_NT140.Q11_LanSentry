from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from logger_setup import alert
from config import TRUSTED_APS
from state import StateStore

state = StateStore()


def parse_fingerprint(pkt):
    ssid = channel = rsn = None
    elt = pkt.getlayer(Dot11Elt)

    while elt:
        if elt.ID == 0:
            ssid = elt.info.decode(errors="ignore")
        elif elt.ID == 3:
            channel = elt.info[0]
        elif elt.ID == 48:
            rsn = elt.info.hex()
        elt = elt.payload.getlayer(Dot11Elt)

    return ssid, channel, rsn


def wifi_packet_cb(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return

    bssid = pkt[Dot11].addr3
    ssid, channel, rsn = parse_fingerprint(pkt)

    state.update_ap(bssid, ssid)
    fp = {"ssid": ssid, "channel": channel, "rsn": rsn}

    old = state.ap_fingerprint.get(bssid)
    if old:
        if old["ssid"] == ssid and old["rsn"] != rsn:
            alert("warning", f"Rogue AP security mismatch: {ssid}")

    state.ap_fingerprint[bssid] = fp
