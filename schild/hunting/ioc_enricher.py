import requests
import json
import os
from typing import Dict, Optional, List
from datetime import datetime

from schild.core.config import (
    VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY,
    COLORS,
)
from schild.core.memory import SchildMemory


class IOCEnricher:
    """Enriches IOCs from multiple threat intelligence sources."""

    def __init__(self, memory: SchildMemory):
        self.memory = memory
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "SCHILD-ThreatHunter/2.0"})

    def enrich(self, ioc_type: str, value: str) -> Dict:
        """
        Enrich a single IOC.

        Args:
            ioc_type: 'ip' | 'domain' | 'hash' | 'url'
            value: The IOC value to look up

        Returns:
            Enrichment result dict
        """
        result = {
            "ioc_type": ioc_type,
            "value": value,
            "sources": {},
            "overall_threat_score": 0.0,
            "verdict": "unknown",
            "timestamp": datetime.now().isoformat(),
        }

        if ioc_type == "ip":
            if VIRUSTOTAL_API_KEY:
                result["sources"]["virustotal"] = self._vt_ip(value)
            if ABUSEIPDB_API_KEY:
                result["sources"]["abuseipdb"] = self._abuseipdb(value)
            if SHODAN_API_KEY:
                result["sources"]["shodan"] = self._shodan_ip(value)

        elif ioc_type == "domain":
            if VIRUSTOTAL_API_KEY:
                result["sources"]["virustotal"] = self._vt_domain(value)

        elif ioc_type == "hash":
            if VIRUSTOTAL_API_KEY:
                result["sources"]["virustotal"] = self._vt_hash(value)

        # Calculate overall threat score (0.0 - 1.0)
        scores = []
        for source, data in result["sources"].items():
            if data and "threat_score" in data:
                scores.append(data["threat_score"])
        if scores:
            result["overall_threat_score"] = sum(scores) / len(scores)

        if result["overall_threat_score"] >= 0.7:
            result["verdict"] = "malicious"
        elif result["overall_threat_score"] >= 0.4:
            result["verdict"] = "suspicious"
        elif result["overall_threat_score"] > 0:
            result["verdict"] = "clean"

        # Persist to memory
        self.memory.upsert_ioc(
            ioc_type=ioc_type,
            value=value,
            source="enricher",
            confidence=result["overall_threat_score"],
            tags=[result["verdict"]],
        )

        return result

    def enrich_bulk(self, iocs: List[Dict]) -> List[Dict]:
        """Enrich a list of IOCs. Each dict must have 'ioc_type' and 'value'."""
        results = []
        for ioc in iocs:
            try:
                r = self.enrich(ioc.get("ioc_type", "ip"), ioc.get("value", ""))
                results.append(r)
                verdict = r["verdict"]
                color = COLORS["error"] if verdict == "malicious" else COLORS["warning"] if verdict == "suspicious" else COLORS["success"]
                print(f"{color}  [{verdict.upper()}] {ioc['ioc_type']}:{ioc['value']} (score: {r['overall_threat_score']:.2f}){COLORS['reset']}")
            except Exception as e:
                print(f"{COLORS['error']}  Enrichment error for {ioc.get('value','?')}: {e}{COLORS['reset']}")
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # VirusTotal
    # ─────────────────────────────────────────────────────────────────────────

    def _vt_ip(self, ip: str) -> Optional[Dict]:
        try:
            r = self._session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                attr = r.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = max(sum(stats.values()), 1)
                return {
                    "malicious_engines": malicious,
                    "total_engines": total,
                    "threat_score": malicious / total,
                    "country": attr.get("country", "N/A"),
                    "reputation": attr.get("reputation", 0),
                    "asn": attr.get("asn", "N/A"),
                    "as_owner": attr.get("as_owner", "N/A"),
                }
        except Exception as e:
            return {"error": str(e)}
        return None

    def _vt_domain(self, domain: str) -> Optional[Dict]:
        try:
            r = self._session.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                attr = r.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = max(sum(stats.values()), 1)
                return {
                    "malicious_engines": malicious,
                    "total_engines": total,
                    "threat_score": malicious / total,
                    "categories": list((attr.get("categories") or {}).values())[:5],
                    "registrar": attr.get("registrar", "N/A"),
                }
        except Exception as e:
            return {"error": str(e)}
        return None

    def _vt_hash(self, hash_val: str) -> Optional[Dict]:
        try:
            r = self._session.get(
                f"https://www.virustotal.com/api/v3/files/{hash_val}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                attr = r.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = max(sum(stats.values()), 1)
                return {
                    "malicious_engines": malicious,
                    "total_engines": total,
                    "threat_score": malicious / total,
                    "file_name": attr.get("meaningful_name", "unknown"),
                    "file_type": attr.get("type_description", "N/A"),
                    "size": attr.get("size", 0),
                }
        except Exception as e:
            return {"error": str(e)}
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # AbuseIPDB
    # ─────────────────────────────────────────────────────────────────────────

    def _abuseipdb(self, ip: str) -> Optional[Dict]:
        try:
            r = self._session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "abuse_confidence_score": score,
                    "threat_score": score / 100,
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "is_tor": data.get("isTor", False),
                }
        except Exception as e:
            return {"error": str(e)}
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Shodan
    # ─────────────────────────────────────────────────────────────────────────

    def _shodan_ip(self, ip: str) -> Optional[Dict]:
        try:
            r = self._session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulns", [])
                ports = data.get("ports", [])
                return {
                    "open_ports": ports[:20],
                    "known_vulnerabilities": list(vulns)[:10],
                    "threat_score": min(len(vulns) * 0.1, 1.0),
                    "country": data.get("country_name", "N/A"),
                    "org": data.get("org", "N/A"),
                    "os": data.get("os", "N/A"),
                    "hostnames": data.get("hostnames", [])[:5],
                }
        except Exception as e:
            return {"error": str(e)}
        return None
