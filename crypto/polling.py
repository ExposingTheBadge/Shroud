"""
SHROUD adaptive client-side polling.

For Rule-2-compliant message pickup the client polls the relay for any
queued routing tags. On a desktop client we can poll aggressively
(every 5 seconds); on a phone running on battery we must throttle to
preserve power, while still feeling near-instant when the user is
actively using the app.

This module computes "what should the next poll interval be" given a
small set of environmental inputs. The actual scheduling (timers,
foreground service, WorkManager) is per-platform; this module is the
shared policy.

Policy
------

We classify the client state into one of these modes:

  FOREGROUND        user has the app on screen          5 sec
  RECENT_FOREGROUND backgrounded < 60 sec ago           10 sec
  BACKGROUND_PLUGGED app backgrounded but device on AC  30 sec
  BACKGROUND_BATTERY app backgrounded, on battery       60 sec
  LOW_BATTERY       battery < 15% and not on AC         180 sec
  DOZE              OS says we are in deep sleep        600 sec
  OFFLINE           network unreachable                 retry with backoff

The cover-traffic loop (separate concern) lays down a constant rate of
decoy traffic so adversaries can't time-correlate against poll bursts;
this module only controls real polls.

Why these numbers
-----------------

  - 5 sec foreground keeps perceived latency under a second for incoming
    text messages (round-trip to relay + render).
  - 60 sec background battery balances "missed call by 1 min" against
    "phone dies in an hour" — about 1 mWh per poll on a typical phone.
  - 180 sec low-battery lets the user keep the app alive past 90 minutes
    of standby on a low charge.
  - 600 sec doze respects Android's Doze restrictions; outside Doze the
    app gets a maintenance window roughly every 10 minutes.

The actual numbers can be tuned per-deployment via the constructor.

Rule compliance
---------------
Orthogonal — this is local power management. Bonus: low polling
frequencies reduce the count of /fetch-anon requests per device, which
incrementally widens the metadata gap an attacker would need to
deanonymize a device by traffic-fingerprint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PollMode(Enum):
    FOREGROUND         = "foreground"
    RECENT_FOREGROUND  = "recent_foreground"
    BACKGROUND_PLUGGED = "background_plugged"
    BACKGROUND_BATTERY = "background_battery"
    LOW_BATTERY        = "low_battery"
    DOZE               = "doze"
    OFFLINE            = "offline"


@dataclass
class PollPolicy:
    foreground_seconds: int         = 5
    recent_foreground_seconds: int  = 10
    background_plugged_seconds: int = 30
    background_battery_seconds: int = 60
    low_battery_seconds: int        = 180
    doze_seconds: int               = 600
    offline_initial_seconds: int    = 8
    offline_max_seconds: int        = 240

    # Thresholds
    recent_foreground_grace_seconds: int = 60
    low_battery_percent: int             = 15


@dataclass
class ClientState:
    foreground: bool
    plugged_in: bool
    battery_percent: int      # 0..100
    in_doze: bool
    network_reachable: bool
    seconds_since_foregrounded: int = 0
    consecutive_offline_failures: int = 0


def next_poll_interval(state: ClientState, policy: Optional[PollPolicy] = None) -> int:
    """Return the recommended seconds-until-next-poll for the given
    client state."""
    p = policy or PollPolicy()
    mode = _classify(state, p)

    if mode == PollMode.OFFLINE:
        # Exponential backoff with a ceiling.
        n = max(0, state.consecutive_offline_failures)
        sleep = p.offline_initial_seconds * (2 ** n)
        return min(sleep, p.offline_max_seconds)

    if mode == PollMode.FOREGROUND:
        return p.foreground_seconds
    if mode == PollMode.RECENT_FOREGROUND:
        return p.recent_foreground_seconds
    if mode == PollMode.BACKGROUND_PLUGGED:
        return p.background_plugged_seconds
    if mode == PollMode.BACKGROUND_BATTERY:
        return p.background_battery_seconds
    if mode == PollMode.LOW_BATTERY:
        return p.low_battery_seconds
    if mode == PollMode.DOZE:
        return p.doze_seconds
    return p.background_battery_seconds


def _classify(s: ClientState, p: PollPolicy) -> PollMode:
    if not s.network_reachable:
        return PollMode.OFFLINE
    if s.in_doze:
        return PollMode.DOZE
    if not s.plugged_in and s.battery_percent <= p.low_battery_percent:
        return PollMode.LOW_BATTERY
    if s.foreground:
        return PollMode.FOREGROUND
    if s.seconds_since_foregrounded <= p.recent_foreground_grace_seconds:
        return PollMode.RECENT_FOREGROUND
    if s.plugged_in:
        return PollMode.BACKGROUND_PLUGGED
    return PollMode.BACKGROUND_BATTERY


# ── Self-test ────────────────────────────────────────────────────────


def _self_test() -> None:
    # Foreground = fastest
    s = ClientState(foreground=True, plugged_in=False, battery_percent=80,
                    in_doze=False, network_reachable=True)
    assert next_poll_interval(s) == 5

    # Recent foreground
    s = ClientState(foreground=False, plugged_in=False, battery_percent=80,
                    in_doze=False, network_reachable=True,
                    seconds_since_foregrounded=30)
    assert next_poll_interval(s) == 10

    # Background plugged
    s = ClientState(foreground=False, plugged_in=True, battery_percent=50,
                    in_doze=False, network_reachable=True,
                    seconds_since_foregrounded=300)
    assert next_poll_interval(s) == 30

    # Background battery
    s = ClientState(foreground=False, plugged_in=False, battery_percent=50,
                    in_doze=False, network_reachable=True,
                    seconds_since_foregrounded=300)
    assert next_poll_interval(s) == 60

    # Low battery (overrides background)
    s = ClientState(foreground=False, plugged_in=False, battery_percent=10,
                    in_doze=False, network_reachable=True,
                    seconds_since_foregrounded=300)
    assert next_poll_interval(s) == 180

    # Low battery does NOT trigger when plugged in even at low percent
    s = ClientState(foreground=False, plugged_in=True, battery_percent=10,
                    in_doze=False, network_reachable=True,
                    seconds_since_foregrounded=300)
    assert next_poll_interval(s) == 30

    # Doze beats everything except offline
    s = ClientState(foreground=False, plugged_in=False, battery_percent=80,
                    in_doze=True, network_reachable=True,
                    seconds_since_foregrounded=300)
    assert next_poll_interval(s) == 600

    # Offline backoff
    s = ClientState(foreground=True, plugged_in=True, battery_percent=100,
                    in_doze=False, network_reachable=False,
                    consecutive_offline_failures=0)
    assert next_poll_interval(s) == 8
    s.consecutive_offline_failures = 3
    assert next_poll_interval(s) == 64
    s.consecutive_offline_failures = 20
    assert next_poll_interval(s) == 240  # capped

    print("polling self-tests passed.")


if __name__ == "__main__":
    _self_test()
