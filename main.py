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

split_from_regex = re.compile('(?P<from_label>.*)<(?P<from_address>.*)>$')
address_domain_regex = re.compile('.*@(?P<domain>[\.\w-]+)')


def parseFromHeader(value):
    """Split 'From:' header into label and address values."""
    match = split_from_regex.match(value)
    result = {
        'label': match.group('from_label').strip(),
        'address': match.group('from_address').strip()
    }
    result['label_domain'] = getDomainFromLabel(result['label'])
    result['address_domain'] = getDomainFromAddress(result['address'])
    return result


def getDomainFromLabel(label):
    """ Check whether given 'From:' header label contains something that looks like an email address."""
    match = address_domain_regex.match(label)
    return match.group('domain').strip() if match is not None else None


def getDomainFromAddress(address):
    match = address_domain_regex.match(address)
    return match.group('domain').strip() if match is not None else None


class SuspiciousFrom(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        self.reset()
        logger.info(f"({self.id}) Instanciated.")

    def reset(self):
        self.final_result = Milter.ACCEPT
        self.new_headers = []

    def header(self, field, value):
        """Header hook gets called for every header within the email processed."""
        if field.lower() == 'from':
            logger.debug(f"({self.id}) Got \"From:\" header raw value: '{value}'")
            value = value.strip('\n').strip()
            if value == '':
                logger.info(f"Got empty from header value! WTF! Skipping.")
                return Milter.CONTINUE
            data = parseFromHeader(value)
            logger.info(f"({self.id}) Label: '{data['label']}', Address: '{data['address']}'")
            if data['label_domain'] is not None:
                logger.debug(f"({self.id}) Label '{data['label']}' contains an address with domain '{data['label_domain']}'.")
                if data['label_domain'].lower() == data['address_domain'].lower():
                    logger.info(f"({self.id}) Label domain '{data['label_domain']}' matches address domain '{data['address_domain']}'. Good!")
                    self.new_headers.append({'name': 'X-From-Checked', 'value': 'OK - Label domain matches address domain'})
                else:
                    logger.info(f"({self.id}) Label domain '{data['label_domain']}' did NOT match address domain '{data['address_domain']}'. BAD!")
                    self.new_headers.append({'name': 'X-From-Checked', 'value': 'FAIL - Label domain does NOT match address domain'})
            else:
                # Supposedly no additional address in the label, accept it for now
                # TODO: Also decode utf-8 weirdness and check in there
                logger.info(f"({self.id}) Label '{data['label']}' probably did not contain an address. Everything is fine.")
                self.new_headers.append({'name': 'X-From-Checked', 'value': 'OK - No address found in label'})
                self.final_result = Milter.ACCEPT
        # Use continue here, so we can reach eom hook.
        # TODO: Log and react if multiple From-headers are found?
        return Milter.CONTINUE

    def eom(self):
        """EOM hook gets called at the end of message processed. Headers and final verdict are applied only here."""
        logger.info(f"({self.id}) EOM: Final verdict is {self.final_result}. New headers: {self.new_headers}")
        for new_header in self.new_headers:
            self.addheader(new_header['name'], new_header['value'])
        logger.info(f"({self.id}) EOM: Reseting self.")
        self.reset()
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
