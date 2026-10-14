"""Synthetic benchmark for the account-takeover detector: generated benign account
histories and scripted attack scenarios, scored for recall per scenario and
false-positive rate on benign accounts. Deterministic for a given seed."""

from __future__ import annotations

import random
from dataclasses import dataclass

from .ato import AccountTakeoverDetector, CampaignDetector, Event

CITIES = {  # country -> (lat, lon)
    "US-SF": ("US", 37.77, -122.42), "US-NY": ("US", 40.71, -74.01), "US-AUS": ("US", 30.27, -97.74),
    "US-CHI": ("US", 41.88, -87.63), "NG-LAG": ("NG", 6.52, 3.38), "RU-MOW": ("RU", 55.75, 37.62),
    "BR-SAO": ("BR", -23.55, -46.63), "DE-BER": ("DE", 52.52, 13.40), "IN-BLR": ("IN", 12.97, 77.59),
}
SCENARIOS = ("stuffing_then_chain", "new_country_payout", "impossible_travel_reset",
             "mass_messaging_after_new_device", "mfa_disable_recovery", "shared_ip_campaign",
             "quiet_new_device_payout", "stolen_known_device")
BENIGN_KINDS = ("new_phone", "trip", "profile", "reset_at_home", "busy_day",
                "forgot_password", "new_phone_and_email", "abroad_trip_reset", "new_isp")


@dataclass
class Account:
    id: str
    home: str
    device: str
    asn: str
    ip: str
    msg_rate: float  # per hour


class AtoSynth:
    def __init__(self, seed: int = 0) -> None:
        self.rng = random.Random(seed)
        self.t0 = 1_780_000_000.0

    def account(self, k: int) -> Account:
        home = self.rng.choice([c for c in CITIES if c.startswith("US")])
        return Account(f"acct{k:04d}", home, f"dev{k:04d}", f"AS{self.rng.randrange(100, 999)}",
                       f"10.{k // 256}.{k % 256}.{self.rng.randrange(1, 254)}", self.rng.choice((0.2, 0.5, 1.0, 2.0)))

    def _login(self, a: Account, ts: float, where: str | None = None, device: str | None = None,
               ip: str | None = None, asn: str | None = None, kind: str = "login") -> Event:
        country, lat, lon = CITIES[where or a.home]
        return Event(a.id, kind, ts, ip or a.ip, device or a.device, country, asn or a.asn, lat, lon)

    def history(self, a: Account, days: int = 30) -> list[Event]:
        """Normal life: logins most days at usual hours, a few messages, occasional travel
        within the country, a rare legitimate password reset."""
        ev: list[Event] = []
        t = self.t0
        for d in range(days):
            day = t + d * 86400
            if self.rng.random() < 0.8:
                hour = self.rng.choice((8, 9, 12, 13, 18, 19, 20, 21, 22))
                where = a.home if self.rng.random() < 0.9 else self.rng.choice([c for c in CITIES if c.startswith("US")])
                lt = day + hour * 3600 + self.rng.randrange(0, 3600)
                ev.append(self._login(a, lt, where))
                for m in range(int(self.rng.expovariate(1 / max(a.msg_rate, 0.1)))):
                    ev.append(Event(a.id, "message_sent", lt + 60 + m * 120))
                if self.rng.random() < 0.02:
                    ev.append(Event(a.id, "password_reset", lt + 300, a.ip, a.device))
        return sorted(ev, key=lambda e: e.ts)

    def benign_tail(self, a: Account, start: float) -> list[Event]:
        """A plausible-but-legitimate day: new phone, a trip, a profile edit, normal messaging."""
        kind = BENIGN_KINDS[self.rng.randrange(len(BENIGN_KINDS))]
        ev = []
        if kind == "new_phone":
            ev.append(self._login(a, start, device="dev-new-" + a.id))
            ev.append(Event(a.id, "message_sent", start + 200))
        elif kind == "trip":
            ev.append(self._login(a, start, where=self.rng.choice(("US-NY", "US-CHI", "DE-BER"))))
            ev.append(Event(a.id, "profile_change", start + 400, a.ip, a.device))
        elif kind == "profile":
            ev.append(self._login(a, start))
            ev.append(Event(a.id, "profile_change", start + 100, a.ip, a.device))
            ev.append(Event(a.id, "email_change", start + 200, a.ip, a.device))
        elif kind == "reset_at_home":
            ev.append(Event(a.id, "login_failed", start - 120, a.ip, a.device))
            ev.append(Event(a.id, "login_failed", start - 60, a.ip, a.device))
            ev.append(self._login(a, start))
            ev.append(Event(a.id, "password_reset", start + 60, a.ip, a.device))
        elif kind == "forgot_password":
            # six wrong guesses from the usual device, then success and a reset
            for k in range(6):
                ev.append(self._login(a, start - 400 + k * 50, kind="login_failed"))
            ev.append(self._login(a, start))
            ev.append(Event(a.id, "password_reset", start + 30, a.ip, a.device))
        elif kind == "new_phone_and_email":
            ev.append(self._login(a, start, device="dev-new-" + a.id))
            ev.append(Event(a.id, "email_change", start + 300, a.ip, "dev-new-" + a.id))
        elif kind == "abroad_trip_reset":
            ip = f"192.0.2.{self.rng.randrange(1, 254)}"
            ev.append(self._login(a, start, where=self.rng.choice(("DE-BER", "IN-BLR", "BR-SAO")),
                                  ip=ip, asn="AS777"))
            ev.append(Event(a.id, "password_reset", start + 600, ip, a.device))
        elif kind == "new_isp":
            ip = f"192.0.2.{self.rng.randrange(1, 254)}"
            ev.append(self._login(a, start, ip=ip, asn=f"AS{self.rng.randrange(1000, 9999)}"))
            ev.append(Event(a.id, "profile_change", start + 100, ip, a.device))
            for m in range(6):
                ev.append(Event(a.id, "message_sent", start + 200 + m * 60))
        else:
            ev.append(self._login(a, start))
            for m in range(8):
                ev.append(Event(a.id, "message_sent", start + 100 + m * 60))
        return ev

    def attack(self, a: Account, start: float, scenario: str, attacker_ip: str = "203.0.113.7") -> list[Event]:
        ev: list[Event] = []
        far = self.rng.choice(("NG-LAG", "RU-MOW", "BR-SAO", "IN-BLR"))
        adev, aasn = "dev-attacker", "AS666"
        if scenario == "stuffing_then_chain":
            for k in range(8):
                ev.append(self._login(a, start - 500 + k * 50, far, adev, attacker_ip, aasn, kind="login_failed"))
            ev.append(self._login(a, start, far, adev, attacker_ip, aasn))
            ev.append(Event(a.id, "password_reset", start + 60, attacker_ip, adev))
            ev.append(Event(a.id, "email_change", start + 120, attacker_ip, adev))
            for m in range(25):
                ev.append(Event(a.id, "message_sent", start + 200 + m * 10))
        elif scenario == "new_country_payout":
            ev.append(self._login(a, start, far, adev, attacker_ip, aasn))
            ev.append(Event(a.id, "payout_change", start + 90, attacker_ip, adev))
        elif scenario == "impossible_travel_reset":
            ev.append(self._login(a, start - 1800, a.home))
            ev.append(self._login(a, start, far, adev, attacker_ip, aasn))
            ev.append(Event(a.id, "password_reset", start + 30, attacker_ip, adev))
        elif scenario == "mass_messaging_after_new_device":
            ev.append(self._login(a, start, a.home, adev, attacker_ip, aasn))
            for m in range(40):
                ev.append(Event(a.id, "message_sent", start + 30 + m * 5))
        elif scenario == "mfa_disable_recovery":
            ev.append(self._login(a, start, far, adev, attacker_ip, aasn))
            ev.append(Event(a.id, "mfa_disabled", start + 40, attacker_ip, adev))
            ev.append(Event(a.id, "recovery_change", start + 80, attacker_ip, adev))
        elif scenario == "shared_ip_campaign":
            ev.append(self._login(a, start, a.home, adev, attacker_ip, aasn))
            ev.append(Event(a.id, "email_change", start + 60, attacker_ip, adev))
        elif scenario == "quiet_new_device_payout":
            # patient attacker: new device in the victim's own country, one change, no noise
            ev.append(self._login(a, start, a.home, adev, "198.51.100.23", aasn))
            ev.append(Event(a.id, "payout_change", start + 2400, "198.51.100.23", adev))
        elif scenario == "stolen_known_device":
            # physical theft or malware: known device and IP, only the change chain is odd
            ev.append(self._login(a, start))
            ev.append(Event(a.id, "mfa_disabled", start + 30, a.ip, a.device))
            ev.append(Event(a.id, "recovery_change", start + 60, a.ip, a.device))
            ev.append(Event(a.id, "payout_change", start + 90, a.ip, a.device))
        else:
            raise ValueError(scenario)
        return ev


def run_ato_benchmark(n_accounts: int = 200, seed: int = 0,
                      detector: AccountTakeoverDetector | None = None) -> dict:
    synth = AtoSynth(seed)
    det = detector or AccountTakeoverDetector()
    accounts = [synth.account(k) for k in range(n_accounts)]
    start = synth.t0 + 31 * 86400 + 12 * 3600
    # campaign: the shared attacker IP hits many accounts first, so CampaignDetector can
    # feed attacker_ips into the per-account detector (the cross-signal in action).
    all_events: list[Event] = []
    per_account: dict[str, tuple[list[Event], list[Event], str]] = {}
    for i, a in enumerate(accounts):
        hist = synth.history(a)
        if i % 2 == 0:
            tail, label = synth.benign_tail(a, start + i * 7), "benign"
        else:
            label = SCENARIOS[(i // 2) % len(SCENARIOS)]
            tail = synth.attack(a, start + i * 7, label)
        per_account[a.id] = (hist, tail, label)
        all_events += hist + tail
    campaigns = CampaignDetector().assess(all_events)
    det_with_ips = AccountTakeoverDetector(**{**det.__dict__, "attacker_ips": {c["ip"] for c in campaigns}})

    results = {"n_accounts": n_accounts, "seed": seed, "campaign_alerts": len(campaigns)}
    for name, d in (("per_account", det), ("per_account+campaign_ip", det_with_ips)):
        tp = fp = fn = tn = 0
        by_scenario: dict[str, list[int]] = {}
        for a in accounts:
            hist, tail, label = per_account[a.id]
            w = d.worst(hist + tail, history=hist)
            # "warn" is a step-up challenge, not a detection; flagged = hold or block
            flagged = w is not None and w.action in ("hold", "block")
            if label == "benign":
                fp += flagged
                tn += not flagged
            else:
                tp += flagged
                fn += not flagged
                by_scenario.setdefault(label, []).append(int(flagged))
        rec = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        results[name] = {"recall": round(rec, 3), "fpr": round(fpr, 3),
                         "per_scenario_recall": {k: round(sum(v) / len(v), 3) for k, v in sorted(by_scenario.items())}}
    return results


def ato_report_markdown(res: dict) -> str:
    lines = ["# Account-takeover benchmark", "",
             "Flagged = action hold or block (warn is a step-up challenge, counted as allow here).", "",
             (f"{res['n_accounts']} synthetic accounts (half benign tails, half attack scenarios), "
              f"seed {res['seed']}. Campaign alerts: {res['campaign_alerts']}."), "",
             "| Detector | recall | FPR | " + " | ".join(SCENARIOS) + " |",
             "|---|---|---|" + "---|" * len(SCENARIOS)]
    for name in ("per_account", "per_account+campaign_ip"):
        r = res[name]
        lines.append(f"| {name} | {r['recall']:.2f} | {r['fpr']:.2f} | "
                     + " | ".join(f"{r['per_scenario_recall'].get(s, 0):.2f}" for s in SCENARIOS) + " |")
    return "\n".join(lines) + "\n"
