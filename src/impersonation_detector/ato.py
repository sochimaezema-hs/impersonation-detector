"""Account-takeover leg: explainable risk scoring over an account's login and
post-login event sequence, plus cross-account campaign detection.

The same approach as the message detector: named features, a transparent scoring
function, graduated actions, and a synthetic benchmark. No dependencies. Feed it the
events your platform already logs (logins, failures, password resets, email or payout
changes, messages sent) and it returns a verdict per sensitive event with the reasons.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

SENSITIVE = frozenset({"password_reset", "email_change", "phone_change", "mfa_disabled",
                       "recovery_change", "payout_change", "api_key_created"})
KINDS = ("login", "login_failed", "message_sent", "profile_change", "logout") + tuple(SENSITIVE)

FEATURE_NAMES: tuple[str, ...] = (
    "new_device", "new_country", "new_asn", "impossible_travel", "failed_burst_then_success",
    "failed_burst_known_device", "sensitive_after_new_login", "sensitive_chain", "mfa_or_recovery_weakened", "payout_changed",
    "mass_messaging", "message_rate_anomaly", "ip_velocity", "off_hours", "shared_attacker_ip",
)
# Explainable fixed weights (log-odds). Chosen so single weak signals stay under "warn" and
# the classic takeover chain (new device -> reset -> email change -> mass messages) blocks.
WEIGHTS: dict[str, float] = {
    "new_device": 0.9, "new_country": 1.2, "new_asn": 0.5, "impossible_travel": 2.2,
    "failed_burst_then_success": 2.0, "failed_burst_known_device": 0.5, "sensitive_after_new_login": 1.8, "sensitive_chain": 2.0,
    "mfa_or_recovery_weakened": 1.6, "payout_changed": 1.2, "mass_messaging": 2.0,
    "message_rate_anomaly": 1.2, "ip_velocity": 1.2, "off_hours": 0.4, "shared_attacker_ip": 2.5,
}
BIAS = -3.2


@dataclass(frozen=True)
class Event:
    account_id: str
    kind: str
    ts: float  # seconds since epoch
    ip: str = ""
    device_id: str = ""
    country: str = ""
    asn: str = ""
    lat: float | None = None
    lon: float | None = None
    meta: dict = field(default_factory=dict)


@dataclass
class Baseline:
    """What is normal for one account, learned from its history."""

    devices: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    asns: set[str] = field(default_factory=set)
    hours: Counter = field(default_factory=Counter)
    messages_per_hour: float = 0.0
    n_logins: int = 0

    @classmethod
    def from_history(cls, events: list[Event]) -> Baseline:
        b = cls()
        if not events:
            return b
        logins = [e for e in events if e.kind == "login"]
        for e in logins:
            b.devices.add(e.device_id)
            b.countries.add(e.country)
            b.asns.add(e.asn)
            b.hours[int((e.ts // 3600) % 24)] += 1
        b.n_logins = len(logins)
        msgs = [e for e in events if e.kind == "message_sent"]
        span_h = max(1.0, (events[-1].ts - events[0].ts) / 3600)
        b.messages_per_hour = len(msgs) / span_h
        return b

    @property
    def established(self) -> bool:
        return self.n_logins >= 3


@dataclass
class AtoVerdict:
    account_id: str
    at: float
    trigger: str
    risk: float
    action: str
    reasons: list[str]
    features: dict[str, float]

    def to_dict(self) -> dict:
        return {"account_id": self.account_id, "at": self.at, "trigger": self.trigger,
                "risk": round(self.risk, 4), "action": self.action, "reasons": self.reasons,
                "features": {k: v for k, v in self.features.items() if v}}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


@dataclass
class AccountTakeoverDetector:
    """Score an account's event sequence. Verdicts are produced at every login and
    every sensitive event, using the events in ``window`` seconds before it."""

    window: float = 3600.0
    failed_burst: int = 5
    failed_burst_window: float = 600.0
    max_speed_kmh: float = 900.0
    mass_messages: int = 20
    mass_window: float = 600.0
    rate_anomaly_factor: float = 10.0
    ip_velocity_n: int = 3
    thresholds: tuple[float, float, float] = (0.30, 0.60, 0.85)
    attacker_ips: set[str] = field(default_factory=set)

    def _action(self, risk: float) -> str:
        warn, hold, block = self.thresholds
        return "block" if risk >= block else "hold" if risk >= hold else "warn" if risk >= warn else "allow"

    def _features(self, events: list[Event], i: int, base: Baseline) -> tuple[dict[str, float], list[str]]:
        e = events[i]
        f = {k: 0.0 for k in FEATURE_NAMES}
        why: list[str] = []
        recent = [x for x in events[:i] if e.ts - x.ts <= self.window]
        last_login = next((x for x in reversed(events[:i + 1]) if x.kind == "login"), None)
        # novelty relative to baseline (only meaningful once a baseline exists)
        if base.established and last_login is not None:
            if last_login.device_id and last_login.device_id not in base.devices:
                f["new_device"] = 1.0
                why.append(f"login from unseen device {last_login.device_id!r}")
            if last_login.country and last_login.country not in base.countries:
                f["new_country"] = 1.0
                why.append(f"login from unseen country {last_login.country}")
            if last_login.asn and last_login.asn not in base.asns:
                f["new_asn"] = 1.0
            hour = int((last_login.ts // 3600) % 24)
            if base.hours and base.hours[hour] == 0 and sum(base.hours.values()) >= 10:
                f["off_hours"] = 1.0
        # impossible travel between the two most recent logins
        logins = [x for x in events[:i + 1] if x.kind == "login" and x.lat is not None]
        if len(logins) >= 2:
            a, b = logins[-2], logins[-1]
            dt_h = max((b.ts - a.ts) / 3600, 1e-6)
            km = haversine_km(a.lat, a.lon, b.lat, b.lon)
            if km > 100 and km / dt_h > self.max_speed_kmh:
                f["impossible_travel"] = 1.0
                why.append(f"impossible travel: {km:.0f} km in {dt_h * 60:.0f} min")
        # credential stuffing / spraying burst then success
        if e.kind == "login":
            fails = [x for x in events[:i] if x.kind == "login_failed" and e.ts - x.ts <= self.failed_burst_window]
            if len(fails) >= self.failed_burst:
                # A burst from the account's own device is a forgotten password; from an
                # unseen device or IP it is credential stuffing or guessing.
                known = base.established and all(
                    (x.device_id and x.device_id in base.devices) or (x.ip and x.ip == e.ip and not f["new_device"])
                    for x in fails)
                if known:
                    f["failed_burst_known_device"] = 1.0
                else:
                    f["failed_burst_then_success"] = 1.0
                    why.append(f"{len(fails)} failed logins in the {self.failed_burst_window / 60:.0f} min before success")
        # sensitive changes
        sens = [x for x in recent + [e] if x.kind in SENSITIVE]
        if e.kind in SENSITIVE:
            if last_login is not None and (f["new_device"] or f["new_country"] or f["impossible_travel"]
                                           or f["failed_burst_then_success"]):
                f["sensitive_after_new_login"] = 1.0
                why.append(f"{e.kind} shortly after a risky login")
            if len({x.kind for x in sens}) >= 2:
                f["sensitive_chain"] = 1.0
                why.append("chain: " + " -> ".join(x.kind for x in sens))
            if any(x.kind in ("mfa_disabled", "recovery_change") for x in sens):
                f["mfa_or_recovery_weakened"] = 1.0
            if any(x.kind == "payout_change" for x in sens):
                f["payout_changed"] = 1.0
        # messaging burst
        msgs = [x for x in recent + [e] if x.kind == "message_sent" and e.ts - x.ts <= self.mass_window]
        if len(msgs) >= self.mass_messages:
            f["mass_messaging"] = 1.0
            why.append(f"{len(msgs)} messages in {self.mass_window / 60:.0f} min")
        hour_msgs = [x for x in recent + [e] if x.kind == "message_sent"]
        if base.established and base.messages_per_hour > 0 and len(hour_msgs) >= 5 \
                and len(hour_msgs) / (self.window / 3600) >= self.rate_anomaly_factor * base.messages_per_hour:
            f["message_rate_anomaly"] = 1.0
            why.append(f"message rate {len(hour_msgs)}/h vs baseline {base.messages_per_hour:.1f}/h")
        # many IPs in the window
        ips = {x.ip for x in recent + [e] if x.kind == "login" and x.ip}
        if len(ips) >= self.ip_velocity_n:
            f["ip_velocity"] = 1.0
            why.append(f"{len(ips)} distinct login IPs in {self.window / 60:.0f} min")
        if last_login is not None and last_login.ip in self.attacker_ips:
            f["shared_attacker_ip"] = 1.0
            why.append(f"login IP {last_login.ip} seen attacking other accounts")
        return f, why

    def assess(self, events: list[Event], history: list[Event] | None = None) -> list[AtoVerdict]:
        """Verdicts at each login and sensitive event in ``events`` (sorted by time).
        ``history`` builds the baseline; if omitted, the first half of ``events``
        that precedes the first sensitive event is used."""
        events = sorted(events, key=lambda x: x.ts)
        if history is None:
            cut = next((k for k, x in enumerate(events) if x.kind in SENSITIVE), len(events) // 2)
            history = events[:cut]
        base = Baseline.from_history(sorted(history, key=lambda x: x.ts))
        out: list[AtoVerdict] = []
        for i, e in enumerate(events):
            if e.kind not in SENSITIVE and e.kind != "login" and not (
                    e.kind == "message_sent" and i >= self.mass_messages - 1):
                continue
            f, why = self._features(events, i, base)
            z = BIAS + sum(WEIGHTS[k] * v for k, v in f.items())
            risk = 1 / (1 + math.exp(-z))
            if e.kind == "message_sent" and not (f["mass_messaging"] or f["message_rate_anomaly"]):
                continue
            out.append(AtoVerdict(e.account_id, e.ts, e.kind, risk, self._action(risk), why, f))
        return out

    def worst(self, events: list[Event], history: list[Event] | None = None) -> AtoVerdict | None:
        vs = self.assess(events, history)
        return max(vs, key=lambda v: v.risk) if vs else None


@dataclass
class CampaignDetector:
    """Cross-account view: IPs or devices touching many accounts in a short window
    (credential stuffing, password spraying, bot farms)."""

    window: float = 3600.0
    min_accounts: int = 5
    min_failure_ratio: float = 0.5

    def assess(self, events: list[Event]) -> list[dict]:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            if e.ip and e.kind in ("login", "login_failed"):
                by_ip[e.ip].append(e)
        alerts = []
        for ip, evs in by_ip.items():
            evs.sort(key=lambda x: x.ts)
            for start in range(len(evs)):
                win = [x for x in evs[start:] if x.ts - evs[start].ts <= self.window]
                accounts = {x.account_id for x in win}
                if len(accounts) >= self.min_accounts:
                    fails = sum(1 for x in win if x.kind == "login_failed")
                    ratio = fails / len(win)
                    if ratio >= self.min_failure_ratio or len(accounts) >= 3 * self.min_accounts:
                        alerts.append({"ip": ip, "accounts": len(accounts), "attempts": len(win),
                                       "failure_ratio": round(ratio, 2),
                                       "compromised": sorted({x.account_id for x in win if x.kind == "login"}),
                                       "start": evs[start].ts})
                        break
        alerts.sort(key=lambda a: (-a["accounts"], a["ip"]))
        return alerts
