import unittest

from arbiter.ingestion.schema import timestamp


class TimestampCompatibilityTests(unittest.TestCase):
    def test_compact_offsets_are_normalized_to_utc(self):
        for value, expected in (
            ("2026-10-11T12:00:00.000+0000", "2026-10-11T12:00:00+00:00"),
            ("2026-10-11T12:00:00+0530", "2026-10-11T06:30:00+00:00"),
            ("2026-10-11T12:00:00-0430", "2026-10-11T16:30:00+00:00"),
            ("2026-10-11T12:00:00+05:30", "2026-10-11T06:30:00+00:00"),
            ("2026-10-11T12:00:00Z", "2026-10-11T12:00:00+00:00"),
        ):
            with self.subTest(value=value):
                self.assertEqual(timestamp(value), expected)

    def test_invalid_offsets_still_fail_validation(self):
        for value in ("bad", "2026-10-11T12:00:00+9999"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timestamp(value)
