"""Opt-in AWS SDK polling. Standard credential chain; no stored secrets."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import time

from ..base import Collector


class AWSCollector(Collector):
    interval = 60

    def __init__(self, config, checkpoint=None, session=None):
        super().__init__(config, checkpoint)
        self.session = session
        self.client = None

    def _client(self):
        if self.client is None:
            if self.session is None:
                import boto3  # optional, imported only after explicit enable
                self.session = boto3.Session(profile_name=self.config.get("profile") or None,
                                             region_name=self.config["region"])
            from botocore.config import Config
            self.client = self.session.client(self.config["adapter"],
                config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2}))
        return self.client

    def collect(self):
        client = self._client()
        adapter = self.config["adapter"]
        end = datetime.now(timezone.utc)
        start = datetime.fromisoformat(self.checkpoint.get("since", (end - timedelta(minutes=15)).isoformat()))
        if adapter == "cloudtrail":
            # Event history supports management events, one region, last 90d.
            # Overlap protects against eventual consistency; event IDs dedupe.
            token = None
            for _ in range(200):
                kwargs = {"StartTime": start - timedelta(minutes=5), "EndTime": end, "MaxResults": 50}
                if token:
                    kwargs["NextToken"] = token
                page = client.lookup_events(**kwargs)
                for raw in page.get("Events", []):
                    yield raw
                token = page.get("NextToken")
                if not token:
                    break
                if self.stop_event.wait(.55):  # lookup limit: two requests/sec/region
                    return
            else:
                raise RuntimeError("CloudTrail polling window exceeded page limit")
        else:
            detector = self.config.get("detector_id")
            if not detector:
                detectors = client.list_detectors().get("DetectorIds", [])
                if not detectors:
                    raise RuntimeError("GuardDuty detector not found")
                detector = detectors[0]
            token = None
            for _ in range(200):
                kwargs = {"DetectorId": detector, "MaxResults": 50,
                          "FindingCriteria": {"Criterion": {"updatedAt": {"Gte": int((start - timedelta(minutes=5)).timestamp() * 1000)}}}}
                if token:
                    kwargs["NextToken"] = token
                page = client.list_findings(**kwargs)
                ids = page.get("FindingIds", [])
                if ids:
                    for raw in client.get_findings(DetectorId=detector, FindingIds=ids).get("Findings", []):
                        yield raw
                token = page.get("NextToken")
                if not token:
                    break
                if self.stop_event.wait(.1):
                    return
            else:
                raise RuntimeError("GuardDuty polling window exceeded page limit")
        # Advance only when all yielded events have been durably accepted.
        self.checkpoint["since"] = end.isoformat()
        self.error = ""
        self.status = "Connected"
