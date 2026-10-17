import unittest

from common.errors import ValidationError
from threat_service.models import Threat, validate_domain, validate_hash


class ThreatModelTests(unittest.TestCase):
    def test_valid_threats_are_normalised(self):
        ip = Threat(" ip address ", "192.168.1.5", " Scanner ", "high", " AbuseIPDB ")
        self.assertEqual(ip.threat_type, "IP Address")
        self.assertEqual(ip.severity_level, "High")
        self.assertEqual(ip.description, "Scanner")
        self.assertEqual(ip.source, "AbuseIPDB")

        domain = Threat("Domain", "Evil.Example.COM", "Phishing", "Critical", "OSINT")
        self.assertEqual(domain.threat_value, "evil.example.com")

        file_hash = Threat("File Hash", "D41D8CD98F00B204E9800998ECF8427E", "Malware", "Low", "VT")
        self.assertEqual(file_hash.threat_value, "d41d8cd98f00b204e9800998ecf8427e")

    def test_free_text_types_accept_any_value(self):
        self.assertEqual(
            Threat("Malware Signature", "Trojan.Win32.Agent", "d", "Medium", "s").threat_value,
            "Trojan.Win32.Agent")
        self.assertEqual(Threat("Other", "odd-indicator", "d", "Low", "s").threat_value,
                         "odd-indicator")

    def test_ipv6_is_accepted(self):
        threat = Threat("IP Address", "2001:db8::1", "d", "Low", "s")
        self.assertEqual(threat.threat_value, "2001:db8::1")

    def test_invalid_ip(self):
        for value in ("999.1.1.1", "1.2.3", "abc", "192.168.1.5/24", 123, None):
            with self.assertRaises(ValidationError, msg=repr(value)):
                Threat("IP Address", value, "d", "High", "s")

    def test_invalid_domain(self):
        for value in ("not a domain", "nodots", "-bad.com", "bad-.com", "a..com",
                      "evil.c", "http://evil.com"):
            with self.assertRaises(ValidationError, msg=value):
                validate_domain(value)

    def test_hash_lengths(self):
        for length in (32, 40, 64):
            self.assertEqual(validate_hash("a" * length), "a" * length)
        for value in ("a" * 31, "a" * 33, "a" * 65, "g" * 32, "xyz"):
            with self.assertRaises(ValidationError, msg=value):
                validate_hash(value)

    def test_invalid_type_and_severity(self):
        with self.assertRaises(ValidationError):
            Threat("Bogus", "a", "d", "High", "s")
        with self.assertRaises(ValidationError):
            Threat("Other", "a", "d", "Urgent", "s")

    def test_required_text_fields(self):
        with self.assertRaises(ValidationError):
            Threat("Other", "a", " ", "High", "s")
        with self.assertRaises(ValidationError):
            Threat("Other", "a", "d", "High", "")
        with self.assertRaises(ValidationError):
            Threat("Other", "", "d", "High", "s")

    def test_length_limits(self):
        with self.assertRaises(ValidationError):
            Threat("Other", "a", "d" * 501, "High", "s")
        with self.assertRaises(ValidationError):
            Threat("Other", "a", "d", "High", "s" * 101)


if __name__ == "__main__":
    unittest.main()
