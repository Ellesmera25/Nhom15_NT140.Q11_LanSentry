import logging
from threading import Thread
import requests
from config import LOG_FILE, SLACK_WEBHOOK

logger = logging.getLogger("LanSentry")
logger.setLevel(logging.INFO)

fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(fh)

ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(ch)


def alert(level, msg):
    tsmsg = f"[LanSentry] {msg}"
    if level == "warning":
        logger.warning(tsmsg)
    else:
        logger.info(tsmsg)

    if SLACK_WEBHOOK:
        Thread(
            target=lambda: requests.post(SLACK_WEBHOOK, json={"text": tsmsg}),
            daemon=True
        ).start()
