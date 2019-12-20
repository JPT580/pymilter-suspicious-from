import sys
import logging

import Milter

from email.header import decode_header
from email.utils import getaddresses

import re

import config

# Basic logger that also logs to stdout
# TODO: Improve this a lot.
logger = logging.getLogger(__name__)
logger.setLevel(config.log_level)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(config.log_level)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

# Rough regex to fetch domain values from address-like text
address_domain_regex = re.compile('.*@(?P<domain>[\.\w-]+)')


def get_decoded_header(value):
    """Use python builtins to decode encoding stuff from header properly."""
    decoded_header_items = decode_header(value)
    decoded_header_value = ''
    for item in decoded_header_items:
        decoded_item = item[0].decode(item[1]) if item[1] is not None else item[0]
        if isinstance(decoded_item, bytes):
            decoded_item = decoded_item.decode('ascii')
        decoded_header_value += decoded_item
    return decoded_header_value


def normalizeRawFromHeader(value):
    """Clean up linebreaks and spaces that are not needed."""
    return value.replace('\n', '').replace('\r', '').strip()


def getDomainFromValue(value):
    """ Check whether given 'From:' header label contains something that looks like an email address."""
    match = address_domain_regex.match(value)
    return match.group('domain').strip() if match is not None else None


class SuspiciousFrom(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        self.reset()
        logger.debug(f"({self.id}) Instanciated.")

    def reset(self):
        """It looks like one milter instance can reach eom hook multiple times.
           This allows to re-use an instance in a more clean way."""
        self.final_result = Milter.ACCEPT
        self.new_headers = []

    def header(self, field, value):
        """Header hook gets called for every header within the email processed."""
        if field.lower() == 'from':
            logger.debug(f"({self.id}) Got \"From:\" header raw value: '{value}'")
            value = normalizeRawFromHeader(value)
            if value == '':
                logger.warn(f"Got empty from header value! WTF! Skipping.")
                return Milter.CONTINUE
            decoded_from = get_decoded_header(value)
            logger.debug(f"({self.id}) Decoded from as a whole: '{decoded_from}'")
            data = getaddresses([decoded_from])[0]
            logger.info(f"({self.id}) Label: '{data[0]}', Address: '{data[1]}'")
            if data[0] == '':
                logger.info(f"({self.id}) No label in from header, should be OK!")
                if decoded_from.count('@') > 1:
                    logger.info(f"({self.id}) Raw decoded from header contains multiple '@'-charecters - investigating!")
                self.new_headers.append({'name': 'X-From-Checked', 'value': 'OK - No label specified'})
                self.new_headers.append({'name': 'X-From-Suspicious', 'value': 'NO'})
            else:
                label_domain = getDomainFromValue(data[0])
                address_domain = getDomainFromValue(data[1])
                logger.info(f"({self.id}) Extracted label_domain '{label_domain}' and address_domain '{address_domain}'")
                if label_domain is not None:
                    logger.debug(f"({self.id}) Label '{data[0]}' contains an address with domain '{label_domain}'.")
                    if label_domain.lower() == address_domain.lower():
                        logger.info(f"({self.id}) Label domain '{label_domain}' matches address domain '{address_domain}'. Good!")
                        self.new_headers.append({'name': 'X-From-Checked', 'value': 'OK - Label domain matches address domain'})
                        self.new_headers.append({'name': 'X-From-Suspicious', 'value': 'NO'})
                    else:
                        logger.info(f"({self.id}) Label domain '{label_domain}' did NOT match address domain '{address_domain}'. BAD!")
                        self.new_headers.append({'name': 'X-From-Checked', 'value': 'FAIL - Label domain does NOT match address domain'})
                        self.new_headers.append({'name': 'X-From-Suspicious', 'value': 'YES'})
                else:
                    logger.info(f"({self.id}) No domain found in label. Good!")
                    self.new_headers.append({'name': 'X-From-Checked', 'value': 'OK - No domain found in label.'})
                    self.new_headers.append({'name': 'X-From-Suspicious', 'value': 'NO'})
        # Use continue here, so we can reach eom hook.
        # TODO: Log and react if multiple From-headers are found?
        return Milter.CONTINUE

    def eom(self):
        """EOM hook gets called at the end of message processed. Headers and final verdict are applied only here."""
        logger.info(f"({self.id}) EOM: Final verdict is {self.final_result}. New headers: {self.new_headers}")
        for new_header in self.new_headers:
            self.addheader(new_header['name'], new_header['value'])
        logger.debug(f"({self.id}) EOM: Reseting self.")
        self.reset()
        return self.final_result


def main():
    # TODO: Move this into configuration of some sort.
    Milter.factory = SuspiciousFrom
    logger.info(f"Starting Milter.")
    # This call blocks the main thread.
    # TODO: Improve handling CTRL+C
    Milter.runmilter("SuspiciousFromMilter", config.milter_socket, config.milter_timeout, rmsock=False)
    logger.info(f"Milter finished running.")


if __name__ == "__main__":
    main()
