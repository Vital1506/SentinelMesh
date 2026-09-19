from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sentinelmesh.config import Settings
from sentinelmesh.models import AttackSession, AttackerProfile, ThreatIntelHit


@dataclass(slots=True)
class CachedLookup:
    expires_at: float
    hits: list[ThreatIntelHit]


class ThreatIntelCorrelator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cache: dict[str, CachedLookup] = {}

    async def lookup_ip(self, remote_ip: str) -> list[ThreatIntelHit]:
        cached = self._cache.get(remote_ip)
        now = time.time()
        if cached and cached.expires_at > now:
            return cached.hits
        hits = await asyncio.to_thread(self._lookup_ip_sync, remote_ip)
        self._cache[remote_ip] = CachedLookup(
            expires_at=now + self.settings.intel_cache_ttl_seconds,
            hits=hits,
        )
        return hits

    def _lookup_ip_sync(self, remote_ip: str) -> list[ThreatIntelHit]:
        hits: list[ThreatIntelHit] = []
        if self.settings.alienvault_otx_api_key:
            hits.extend(self._query_otx(remote_ip))
        if self.settings.abuseipdb_api_key:
            hits.extend(self._query_abuseipdb(remote_ip))
        if self.settings.shodan_api_key:
            hits.extend(self._query_shodan(remote_ip))
        if self.settings.vt_api_key:
            hits.extend(self._query_virustotal(remote_ip))
        return hits

    def build_stix_bundle(
        self,
        session: AttackSession,
        profile: AttackerProfile,
        hits: list[ThreatIntelHit],
    ) -> dict[str, Any]:
        observed_at = session.started_at.astimezone(timezone.utc).isoformat()
        observed_end = (session.ended_at or session.started_at).astimezone(timezone.utc).isoformat()
        identity_id = "identity--sentinelmesh"
        ipv4_id = f"ipv4-addr--{profile.remote_ip.replace('.', '-')}"
        indicator_id = f"indicator--{profile.threat_id[:32]}"
        objects = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": observed_at,
                "modified": observed_at,
                "name": "SentinelMesh",
                "identity_class": "system",
            },
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": ipv4_id,
                "value": profile.remote_ip,
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": observed_at,
                "modified": observed_at,
                "name": f"SentinelMesh indicator {profile.threat_id[:12]}",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{profile.remote_ip}']",
                "confidence": int(min(profile.risk_score, 100)),
                "labels": profile.labels,
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{profile.threat_id[12:44]}",
                "created_by_ref": identity_id,
                "created": observed_at,
                "modified": observed_at,
                "first_observed": observed_at,
                "last_observed": observed_end,
                "number_observed": 1,
                "object_refs": [ipv4_id],
            },
        ]
        for index, hit in enumerate(hits, start=1):
            objects.append(
                {
                    "type": "note",
                    "spec_version": "2.1",
                    "id": f"note--{profile.threat_id[index:index + 32]}",
                    "created": observed_at,
                    "modified": observed_at,
                    "abstract": hit.provider,
                    "content": hit.summary,
                    "authors": ["SentinelMesh"],
                    "object_refs": [indicator_id],
                    "labels": hit.labels,
                }
            )
        return {
            "type": "bundle",
            "id": f"bundle--{profile.threat_id}",
            "objects": objects,
        }

    def write_stix_bundle(
        self,
        target_path: str,
        session: AttackSession,
        profile: AttackerProfile,
        hits: list[ThreatIntelHit],
    ) -> None:
        bundle = self.build_stix_bundle(session, profile, hits)
        with open(target_path, "w", encoding="utf-8") as handle:
            json.dump(bundle, handle, indent=2)

    def _query_otx(self, remote_ip: str) -> list[ThreatIntelHit]:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{remote_ip}/general"
        headers = {"X-OTX-API-KEY": self.settings.alienvault_otx_api_key or ""}
        payload = self._fetch_json(url, headers)
        pulse_info = payload.get("pulse_info", {}).get("count", 0)
        if not pulse_info:
            return []
        return [
            ThreatIntelHit(
                provider="AlienVault OTX",
                summary=f"OTX pulse count for {remote_ip}: {pulse_info}",
                confidence=min(0.3 + pulse_info * 0.05, 0.95),
                labels=["otx", "osint"],
                reference_url=f"https://otx.alienvault.com/indicator/ip/{remote_ip}",
            )
        ]

    def _query_abuseipdb(self, remote_ip: str) -> list[ThreatIntelHit]:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={remote_ip}&maxAgeInDays=90"
        headers = {
            "Key": self.settings.abuseipdb_api_key or "",
            "Accept": "application/json",
        }
        payload = self._fetch_json(url, headers)
        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        if score <= 0:
            return []
        return [
            ThreatIntelHit(
                provider="AbuseIPDB",
                summary=f"Abuse confidence score {score}/100 for {remote_ip}",
                confidence=min(score / 100.0, 0.95),
                labels=["abuseipdb", "reputation"],
                reference_url=data.get("domain"),
            )
        ]

    def _query_shodan(self, remote_ip: str) -> list[ThreatIntelHit]:
        url = f"https://api.shodan.io/shodan/host/{remote_ip}?key={self.settings.shodan_api_key}"
        payload = self._fetch_json(url)
        ports = payload.get("ports", [])
        if not ports:
            return []
        return [
            ThreatIntelHit(
                provider="Shodan",
                summary=f"Shodan observed ports {ports[:6]} for {remote_ip}",
                confidence=0.45,
                labels=["shodan", "surface-scan"],
                reference_url=f"https://www.shodan.io/host/{remote_ip}",
            )
        ]

    def _query_virustotal(self, remote_ip: str) -> list[ThreatIntelHit]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{remote_ip}"
        headers = {"x-apikey": self.settings.vt_api_key or ""}
        payload = self._fetch_json(url, headers)
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        if malicious <= 0:
            return []
        return [
            ThreatIntelHit(
                provider="VirusTotal",
                summary=f"VirusTotal marked {remote_ip} malicious in {malicious} engines",
                confidence=min(0.4 + malicious * 0.05, 0.95),
                labels=["virustotal", "malicious"],
                reference_url=f"https://www.virustotal.com/gui/ip-address/{remote_ip}",
            )
        ]

    def _fetch_json(self, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        request = Request(url, headers=headers or {})
        try:
            with urlopen(request, timeout=8) as response:
                raw = response.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError):
            return {}
