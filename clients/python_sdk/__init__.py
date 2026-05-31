"""SHROUD Python client SDK.

See shroud_client.ShroudClient for the entry point. This package is
the reference implementation that all other client ports should match
behaviorally; if you want to verify that your Windows / Android / iOS
client is wire-compatible, run its tests against this SDK.
"""
from .shroud_client import ShroudClient, Contact, ReceivedMessage  # noqa: F401
