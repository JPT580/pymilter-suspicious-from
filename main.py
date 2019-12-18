import time
import sys
import logging

import Milter
from Milter.utils import parse_addr

import re

# Basic logger that also logs to stdout
# TODO: Improve this a lot.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

split_from_regex = re.compile('(?P<from_label>("(.*)")|(.*))(.*)<(?P<from_address>.*)>')

def splitFromHeader(value):
    match = split_from_regex.match(value)
    result = {
        'label': match.group('from_label').strip(),
        'address': match.group('from_address').strip()
    }
    return result

class SuspiciousFrom(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        logger.info(f"{self.id} got fired up.")
        self.milter_final_result = Milter.ACCEPT
        self.new_headers = []

    def header(self, field, value):
        if field.lower() == 'from':
            logger.info(f"Got \"From:\" header with raw value: '{value}'")
            split = splitFromHeader(value)
            logger.info(f"Label: {split['label']}, address: {split['address']}")
            if '@' in split['label']:
                self.milter_final_result = Milter.REJECT

            else:
                self.new_headers.append({'name': 'X-From-Checked', 'value': 'Yes, no address in label.'})
                # Supposedly no additional address in the label, accept it for now
                # TODO: Also decode utf-8 weirdness and check in there
                self.milter_final_result = Milter.ACCEPT
                return Milter.CONTINUE
        else:
            return Milter.CONTINUE

    def eom(self):
        # Finish up message according to results collected on the way.
        for new_header in self.new_headers:
            self.addheader(new_header['name'], new_header['value'])
        return self.milter_final_result


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
