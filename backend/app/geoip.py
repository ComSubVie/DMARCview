"""Offline GeoIP lookups.

The app never sends IP addresses to a third party.  Drop a MaxMind GeoLite2 or
DB-IP Lite ``.mmdb`` file at ``data/geoip/*.mmdb`` (or set ``GEOIP_DB``) and
country information is resolved locally.  Without a database everything still
works — countries simply render as unknown.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from pathlib import Path
from typing import Optional

from .config import get_settings

log = logging.getLogger(__name__)

#: Minimal fallback so the UI does not show bare ISO codes for common origins.
COUNTRY_NAMES = {
    "AT": "Austria", "AU": "Australia", "BE": "Belgium", "BR": "Brazil", "CA": "Canada",
    "CH": "Switzerland", "CN": "China", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
    "ES": "Spain", "EU": "Europe", "FI": "Finland", "FR": "France", "GB": "United Kingdom",
    "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary", "IE": "Ireland", "IL": "Israel",
    "IN": "India", "IT": "Italy", "JP": "Japan", "KR": "South Korea", "LU": "Luxembourg",
    "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand", "PL": "Poland",
    "PT": "Portugal", "RO": "Romania", "RU": "Russia", "SE": "Sweden", "SG": "Singapore",
    "SI": "Slovenia", "SK": "Slovakia", "TR": "Türkiye", "UA": "Ukraine", "US": "United States",
    "ZA": "South Africa",
}


class GeoResolver:
    def __init__(self, path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[Optional[str], Optional[str]]] = {}
        self._reader = None
        self.path = self._find_database(path)
        self._open()

    @staticmethod
    def _find_database(explicit: Optional[str]) -> Optional[Path]:
        if explicit:
            candidate = Path(explicit)
            if candidate.is_file():
                return candidate
            log.warning("GEOIP_DB points at %s but no file exists there", explicit)
        data_dir = get_settings().data_dir
        for directory in (data_dir / "geoip", data_dir):
            if not directory.is_dir():
                continue
            for pattern in ("*country*.mmdb", "*.mmdb"):
                matches = [
                    path for path in sorted(directory.glob(pattern)) if "asn" not in path.name.lower()
                ]
                if matches:
                    return matches[0]
        return None

    def _open(self) -> None:
        if self.path is None:
            return
        try:
            import maxminddb
        except ImportError:  # pragma: no cover - optional dependency
            log.warning("maxminddb is not installed; country resolution disabled")
            return
        try:
            self._reader = maxminddb.open_database(str(self.path))
            log.info("GeoIP database loaded from %s", self.path)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not open GeoIP database %s: %s", self.path, exc)

    @property
    def available(self) -> bool:
        return self._reader is not None

    def lookup(self, ip: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        if not ip:
            return None, None
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        result: tuple[Optional[str], Optional[str]] = (None, None)
        try:
            address = ipaddress.ip_address(ip.strip())
            if address.is_private or address.is_loopback or address.is_reserved or address.is_multicast:
                result = (None, None)
            elif self._reader is not None:
                raw = self._reader.get(str(address)) or {}
                country = raw.get("country") or raw.get("registered_country") or {}
                code = country.get("iso_code")
                if code:
                    name = (country.get("names") or {}).get("en") or COUNTRY_NAMES.get(code, code)
                    result = (code.upper(), name)
        except ValueError:
            result = (None, None)
        except Exception:  # noqa: BLE001 - never fail ingestion because of geo
            result = (None, None)
        with self._lock:
            self._cache[ip] = result
        return result


class AsnResolver:
    """Offline ASN lookup from a MaxMind/DB-IP ``.mmdb`` database."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[Optional[int], Optional[str]]] = {}
        self._reader = None
        self.path = self._find_database(path)
        self._open()

    @staticmethod
    def _find_database(explicit: Optional[str]) -> Optional[Path]:
        if explicit:
            candidate = Path(explicit)
            if candidate.is_file():
                return candidate
            log.warning("GEOIP_ASN_DB points at %s but no file exists there", explicit)
        data_dir = get_settings().data_dir
        for directory in (data_dir / "geoip", data_dir):
            if not directory.is_dir():
                continue
            matches = sorted(directory.glob("*asn*.mmdb"))
            if matches:
                return matches[0]
        return None

    def _open(self) -> None:
        if self.path is None:
            return
        try:
            import maxminddb
        except ImportError:  # pragma: no cover - optional dependency
            return
        try:
            self._reader = maxminddb.open_database(str(self.path))
            log.info("ASN database loaded from %s", self.path)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not open ASN database %s: %s", self.path, exc)

    @property
    def available(self) -> bool:
        return self._reader is not None

    def lookup(self, ip: Optional[str]) -> tuple[Optional[int], Optional[str]]:
        if not ip:
            return None, None
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        result: tuple[Optional[int], Optional[str]] = (None, None)
        try:
            address = ipaddress.ip_address(ip.strip())
            if address.is_private or address.is_loopback or address.is_reserved or address.is_multicast:
                result = (None, None)
            elif self._reader is not None:
                raw = self._reader.get(str(address)) or {}
                number = raw.get("autonomous_system_number")
                org = raw.get("autonomous_system_organization")
                if number:
                    result = (int(number), str(org)[:255] if org else None)
        except ValueError:
            result = (None, None)
        except Exception:  # noqa: BLE001
            result = (None, None)
        with self._lock:
            self._cache[ip] = result
        return result


_resolver: Optional[GeoResolver] = None
_asn_resolver: Optional[AsnResolver] = None
_resolver_lock = threading.Lock()


def get_geo_resolver() -> GeoResolver:
    global _resolver
    with _resolver_lock:
        if _resolver is None:
            _resolver = GeoResolver(get_settings().geoip_db or None)
        return _resolver


def reset_geo_resolver() -> None:
    global _resolver, _asn_resolver
    with _resolver_lock:
        _resolver = None
        _asn_resolver = None


def get_asn_resolver() -> AsnResolver:
    global _asn_resolver
    with _resolver_lock:
        if _asn_resolver is None:
            _asn_resolver = AsnResolver(get_settings().geoip_asn_db or None)
        return _asn_resolver


def country_flag(code: Optional[str]) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in code.upper())
