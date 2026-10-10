"""Explicit scaffolding: these connectors do not collect or claim health."""
from ..base import Collector


class FutureCollector(Collector):
    def start(self, submit, save):
        raise NotImplementedError("Connector is Coming Soon")

    def collect(self):
        raise NotImplementedError("No transport implemented")

    def health(self):
        return {"status": "Coming Soon", "errors": 0, "error": ""}
