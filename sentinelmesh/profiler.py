from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import replace

from sentinelmesh.models import AttackerProfile, AttackSession, ObservedCommand, utc_now


def shannon_entropy(values: list[str]) -> float:
    raw = "".join(values)
    if not raw:
        return 0.0
    counts = Counter(raw)
    total = len(raw)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


class AttackProfiler:
    def build_profile(self, session: AttackSession, commands: list[ObservedCommand]) -> AttackerProfile:
        command_text = [command.command for command in commands] or session.command_history
        cadence_ms = self._estimate_cadence(commands)
        entropy = shannon_entropy(command_text + session.message_samples)
        tool_guess = self._guess_tool(session, command_text)
        risk_score = self._risk_score(session, command_text, entropy)
        source = "|".join(
            [session.remote_ip, session.service, ",".join(command_text[:5]), session.started_at.isoformat()]
        )
        threat_id = hashlib.sha256(source.encode("utf-8")).hexdigest()
        labels = self._labels(command_text, tool_guess, risk_score)
        first_seen = session.started_at
        last_seen = session.ended_at or utc_now()
        return AttackerProfile(
            threat_id=threat_id,
            remote_ip=session.remote_ip,
            tool_guess=tool_guess,
            command_count=len(command_text),
            avg_entropy=entropy,
            cadence_ms=cadence_ms,
            risk_score=risk_score,
            first_seen=first_seen,
            last_seen=last_seen,
            labels=labels,
        )

    def cluster_profiles(self, profiles: list[AttackerProfile]) -> list[AttackerProfile]:
        if len(profiles) < 2:
            return profiles

        try:
            import numpy as np
            from sklearn.cluster import DBSCAN

            features = np.array(
                [
                    [profile.command_count, profile.avg_entropy, profile.cadence_ms, profile.risk_score]
                    for profile in profiles
                ]
            )
            labels = DBSCAN(eps=8.0, min_samples=2).fit_predict(features)
            return [
                replace(profile, cluster_id=f"cluster-{int(label)}" if label >= 0 else None)
                for profile, label in zip(profiles, labels, strict=True)
            ]
        except Exception:
            return [
                replace(profile, cluster_id=f"cluster-{profile.remote_ip.split('.')[0]}")
                for profile in profiles
            ]

    def _estimate_cadence(self, commands: list[ObservedCommand]) -> float:
        if len(commands) < 2:
            return 0.0
        deltas = []
        previous = commands[0].observed_at
        for command in commands[1:]:
            delta = (command.observed_at - previous).total_seconds() * 1000
            deltas.append(delta)
            previous = command.observed_at
        return sum(deltas) / len(deltas)

    def _guess_tool(self, session: AttackSession, commands: list[str]) -> str:
        sample = " ".join(session.message_samples + commands).lower()
        if "nmap" in sample:
            return "nmap"
        if "hydra" in sample or "nc " in sample or "netcat" in sample:
            return "bruteforce-or-proxy"
        if "metasploit" in sample or "meterpreter" in sample:
            return "metasploit"
        if "curl/" in sample or "python-requests" in sample or "urllib" in sample:
            return "automated-http-client"
        if any(command.startswith(("wget ", "curl ", "scp ", "tftp ")) for command in commands):
            return "payload-dropper"
        if any(
            command.startswith("ssh ") or command.startswith("scp ") for command in commands
        ):
            return "lateral-movement"
        return "interactive-shell"

    def _risk_score(self, session: AttackSession, commands: list[str], entropy: float) -> float:
        score = min(len(commands) * 4.5, 35.0)
        score += min(entropy * 3.0, 20.0)
        if any("wget" in command or "curl" in command or "tftp" in command for command in commands):
            score += 20.0
        if any("chmod" in command or "./" in command or ".sh" in command for command in commands):
            score += 15.0
        if any("/etc/passwd" in command or "shadow" in command or ".env" in command for command in commands):
            score += 15.0
        if session.service == "ssh":
            score += 8.0
        if session.remote_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            score = max(0.0, score - 6.0)
        return min(score, 100.0)

    def _labels(self, commands: list[str], tool_guess: str, risk_score: float) -> list[str]:
        labels = [tool_guess]
        if any("wget" in command or "curl" in command or "tftp" in command for command in commands):
            labels.append("download-attempt")
        if any("cat /etc/passwd" in command or "shadow" in command or ".env" in command for command in commands):
            labels.append("credential-discovery")
        if any("chmod" in command or "./" in command or ".sh" in command for command in commands):
            labels.append("execution-attempt")
        if any("ssh " in command or "scp " in command for command in commands):
            labels.append("lateral-movement")
        if risk_score >= 70:
            labels.append("high-risk")
        return labels
