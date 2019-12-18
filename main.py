import time
import sys
import logging

import Milter
from Milter.utils import parse_addr

# Basic logger that also logs to stdout
# TODO: Improve this a lot.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

class SuspiciousFrom(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        logger.info(f"{self.id} got fired up.")

    def header(self, field, value):
        logger.info(f"{self.id} Got header: {field} --> {value}")

def main():
    milter_socket = "inet:7777@127.0.0.1"
    milter_timeout = 60
    Milter.factory = SuspiciousFrom
    logger.info(f"Starting Milter.")
    # This call blocks the main thread.
    Milter.runmilter("SuspiciousFromMilter", milter_socket, milter_timeout, rmsock=False)
    logger.info(f"Milter finished running.")

if __name__ == "__main__":
    logger.debug(f"Hello world!")
    main()
