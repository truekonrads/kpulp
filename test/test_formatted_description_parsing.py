from kpulp import description_to_fields
import unittest


class TestParser(unittest.TestCase):

    def test_message_parser(self):
        msg = """An account was logged off.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSOMESERVER-PROD$\r\n\tAccount Domain:\t\tACME\r\n\tLogon ID:\t\t0xa65162c\r\n\r\nLogon Type:\t\t\t3\r\n\r\nThis event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.\r\n"""
        good_outcome = {
            'Subject Security ID': 'S-1-5-18',
            'Subject Account Name': 'SOMESERVER-PROD$',
            'Subject Account Domain': 'ACME',
            'Subject Logon ID': '0xa65162c',
            'Logon Type': '3'

        }

        fields = description_to_fields(msg)
        self.assertEquals(good_outcome, fields)
