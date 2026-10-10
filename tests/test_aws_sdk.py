"""Optional SDK contract check. No real credentials or network calls."""
import importlib.util
import unittest
from unittest.mock import Mock, patch

from arbiter.ingestion.collectors.aws import AWSCollector


@unittest.skipUnless(importlib.util.find_spec("boto3"), "optional AWS SDK not installed")
class SDKTests(unittest.TestCase):
    def test_profile_region_standard_chain_no_key_parameters(self):
        with patch("boto3.Session") as session_type:
            session = session_type.return_value
            collector = AWSCollector({"adapter": "cloudtrail", "profile": "readonly", "region": "us-east-1"})
            self.assertIs(collector._client(), session.client.return_value)
            session_type.assert_called_once_with(profile_name="readonly", region_name="us-east-1")
            config = session.client.call_args.kwargs["config"]
            self.assertEqual(config.connect_timeout, 5)
            self.assertEqual(config.read_timeout, 10)

    def test_missing_profile_uses_default_chain(self):
        with patch("boto3.Session") as session_type:
            collector = AWSCollector({"adapter": "guardduty", "region": "us-east-1"})
            collector._client()
            session_type.assert_called_once_with(profile_name=None, region_name="us-east-1")
