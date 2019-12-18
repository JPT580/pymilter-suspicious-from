import time
import sys
import logging

import Milter

import re

# Basic logger that also logs to stdout
# TODO: Improve this a lot.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

split_from_regex = re.compile('(?P<from_label>("(.*)")|(.*))(.*)<(?P<from_address>.*)>')
address_domain_regex = re.compile('.*@(?P<domain>[\.\w-]+)')


def splitFromHeader(value):
    """Split 'From:' header into label and address values."""
    match = split_from_regex.match(value)
    return {
        'label': match.group('from_label').strip(),
        'address': match.group('from_address').strip()
    }


def labelContainsAddress(label):
    """ Check whether given 'From:' header label contains something that looks like an email address."""
    return address_domain_regex.match(label) is not None


def labelAndAddressDomainsMatch(split):
    label_domain = address_domain_regex.match(split['label']).group('domain').strip()
    address_domain = address_domain_regex.match(split['address']).group('domain').strip()
    return label_domain.lower() == address_domain.lower()


class SuspiciousFrom(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        self.final_result = Milter.ACCEPT
        self.new_headers = []
        logger.info(f"{self.id} got fired up.")

    def header(self, field, value):
        """Header hook gets called for every header within the email processed."""
        if field.lower() == 'from':
            logger.info(f"Got \"From:\" header with raw value: '{value}'")
            split = splitFromHeader(value)
            logger.info(f"Label: {split['label']}, address: {split['address']}")
            if labelContainsAddress(split['label']):
                logger.info()
                if labelAndAddressDomainsMatch(split):
                    self.new_headers.append({'name': 'X-From-Checked', 'value': 'Maybe multiple domains - no match - BAD!'})
                    self.final_result = Milter.ACCEPT
                else:
                    self.new_headers.append({'name': 'X-From-Checked', 'value': 'Multiple domains - no match - BAD!'})
                    self.final_result = Milter.ACCEPT
            else:
                # Supposedly no additional address in the label, accept it for now
                # TODO: Also decode utf-8 weirdness and check in there
                self.new_headers.append({'name': 'X-From-Checked', 'value': 'Yes, no address in label.'})
                self.final_result = Milter.ACCEPT
        # Use continue here, so we can reach eom hook.
        # TODO: Log and react if multiple From-headers are found?
        return Milter.CONTINUE

    def eom(self):
        """EOM hook gets called at the end of message processed. Headers and final verdict are applied only here."""
        # Finish up message according to results collected on the way.
        for new_header in self.new_headers:
            self.addheader(new_header['name'], new_header['value'])
        return self.final_result


def main():
    # TODO: Move this into configuration of some sort.
    milter_socket = "inet:7777@127.0.0.1"
    milter_timeout = 60
    Milter.factory = SuspiciousFrom
    logger.info(f"Starting Milter.")
    # This call blocks the main thread.
    # TODO: Improve handling CTRL+C
    Milter.runmilter("SuspiciousFromMilter", milter_socket, milter_timeout, rmsock=False)
    logger.info(f"Milter finished running.")


if __name__ == "__main__":
    main()
