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
# Not matching the part in front of @ because greedy and stuff :(
address_domain_regex = re.compile('\@(?P<domain>[\.\w-]+)')


def get_decoded_header(value):
    """Use python builtins to decode encoding stuff from header properly."""
    decoded_header_items = decode_header(value)
    decoded_header_value = ''
    for item in decoded_header_items:
        decoded_item = item[0].decode(item[1], 'ignore') if item[1] is not None else item[0]
        if isinstance(decoded_item, bytes):
            decoded_item = decoded_item.decode('ascii', 'ignore')
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

    def set_suspicious_headers(self, is_suspicious, reason):
        str_okay = "PASS" if not is_suspicious else "FAIL"
        str_suspicious = "YES" if is_suspicious else "NO"
        self.new_headers.append({'name': 'X-From-Checked', 'value': f"{str_okay} - {reason}"})
        self.new_headers.append({'name': 'X-From-Suspicious', 'value': str_suspicious})

    def header(self, field, value):
        """Header hook gets called for every header within the email processed."""
        if field.lower() == 'from':
            logger.debug(f"({self.id}) \"From:\" raw: '{value}'")
            value = normalizeRawFromHeader(value)
            logger.info(f"({self.id}) \"From:\" cleaned: '{value}'")
            if value == '':
                logger.warning(f"\"From:\" header empty! WTF, but nothing to do. OK for now.")
                self.set_suspicious_headers(False, "EMPTY FROM HEADER - WTF")
            else:
                decoded_from = get_decoded_header(value)
                logger.debug(f"({self.id}) \"From:\" decoded raw: '{value}'")
                decoded_from = normalizeRawFromHeader(decoded_from)
                logger.info(f"({self.id}) \"From:\" decoded cleaned: '{decoded_from}'")
                all_domains = address_domain_regex.findall(decoded_from)
                all_domains = [a.lower() for a in all_domains]
                if len(all_domains) == 0:
                    logger.warning(f"({self.id}) No domain in decoded \"From:\" - WTF! OK, though")
                    self.set_suspicious_headers(False, "No domains in decoded FROM")
                elif len(all_domains) == 1:
                    logger.debug(f"({self.id}) Only one domain in decoded \"From:\": '{all_domains[0]}' - OK")
                    self.set_suspicious_headers(False, "Only one domain in decoded FROM")
                else:
                    logger.info(f"({self.id}) Raw decoded from header contains multiple domains: '{all_domains}' - Checking")
                    if len(set(all_domains)) > 1:
                        logger.info(f"({self.id}) Multiple different domains in decoded \"From:\". - NOT OK")
                        self.set_suspicious_headers(True, "Multiple domains in decoded FROM are different")
                    else:
                        logger.info(f"({self.id}) All domains in decoded \"From:\" are identical - OK")
                        self.set_suspicious_headers(False, "Multiple domains in decoded FROM match properly")
        # CONTINUE so we reach eom hook.
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
