import argparse
import time
from threading import Thread
from sniffers.sniffers import start_arp, start_dhcp, start_wifi
from logger_setup import alert


def parse_args():
    p = argparse.ArgumentParser("LanSentry")
    p.add_argument("-i", "--iface", required=True)
    p.add_argument("-w", "--wifi-iface")
    return p.parse_args()


def main():
    args = parse_args()
    alert("info", "LanSentry starting")

    Thread(target=start_arp, args=(args.iface,), daemon=True).start()
    Thread(target=start_dhcp, args=(args.iface,), daemon=True).start()

    if args.wifi_iface:
        Thread(target=start_wifi, args=(args.wifi_iface,), daemon=True).start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
