#!/usr/bin/env python3
"""Download free country and ASN GeoIP databases (DB-IP Lite, CC BY 4.0).

    python3 scripts/fetch_geoip.py [destination-dir]

DB-IP publishes a new file at the start of each month; the script falls back to
the previous two months if this month's file is not online yet.

Some Python installations (notably python.org builds on macOS) ship an
out-of-date CA bundle and fail with ``CERTIFICATE_VERIFY_FAILED``. This script
tries certifi, the common system trust stores and finally the interpreter
default, so it works with a bare ``python3``.

Attribution: IP Geolocation by DB-IP (https://db-ip.com) — CC BY 4.0.
"""

from __future__ import annotations

import argparse
import gzip
import io
import ssl
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

USER_AGENT = "DMARCView/1.0 (+https://github.com/dmarcview)"

#: Trust stores that commonly exist on macOS and Linux hosts.
CA_CANDIDATES = (
    "/etc/ssl/cert.pem",  # macOS, Alpine
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL
    "/usr/local/etc/openssl/cert.pem",  # Intel Homebrew
    "/opt/homebrew/etc/openssl@3/cert.pem",  # Apple Silicon Homebrew
    "/opt/homebrew/etc/ca-certificates/cert.pem",
)


class DownloadError(RuntimeError):
    def __init__(self, message: str, problems: list[str], *, fatal: bool = False):
        super().__init__(message)
        self.problems = problems
        #: A network failure will not be fixed by another CA or month.
        self.fatal = fatal


def month_candidates(today: date, count: int = 3) -> list[str]:
    months: list[str] = []
    year, month = today.year, today.month
    for _ in range(count):
        months.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return months


def build_contexts(ca_file: str | None, insecure: bool) -> list[tuple[str, ssl.SSLContext]]:
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return [("insecure (no verification)", context)]

    contexts: list[tuple[str, ssl.SSLContext]] = []
    if ca_file:
        if not Path(ca_file).is_file():
            raise DownloadError(f"CA bundle not found: {ca_file}", [ca_file])
        try:
            contexts.append((ca_file, ssl.create_default_context(cafile=ca_file)))
        except (OSError, ssl.SSLError) as exc:
            raise DownloadError(f"could not load CA bundle {ca_file}: {exc}", [str(exc)]) from exc
        return contexts

    certifi = None
    try:
        import certifi  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001 - certifi is optional
        certifi = None
    if certifi is not None:
        contexts.append(
            (f"certifi ({certifi.where()})", ssl.create_default_context(cafile=certifi.where()))
        )

    for candidate in CA_CANDIDATES:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            contexts.append((candidate, ssl.create_default_context(cafile=candidate)))
        except (ssl.SSLError, OSError):
            continue

    contexts.append(("interpreter default", ssl.create_default_context()))
    return contexts


def fetch(url: str, contexts: list[tuple[str, ssl.SSLContext]], timeout: int = 60) -> bytes:
    problems: list[str] = []
    for label, context in contexts:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return response.read()
        except urllib.error.HTTPError:
            # The month simply is not published yet: no point trying other CAs.
            raise
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (ssl.SSLError, ssl.SSLCertVerificationError)):
                problems.append(f"{label}: {exc}")
                continue
            raise DownloadError(f"network error: {exc}", [f"{label}: {exc}"], fatal=True) from exc
        except (ssl.SSLError, TimeoutError, ConnectionError) as exc:
            problems.append(f"{label}: {exc}")
            continue
    raise DownloadError("all trust stores failed", problems)


def download(
    dest: Path,
    prefix: str = "dbip-country-lite",
    ca_file: str | None = None,
    insecure: bool = False,
) -> Path:
    contexts = build_contexts(ca_file, insecure)
    if insecure:
        print("WARNING: TLS verification disabled (--insecure)")
    errors: list[str] = []
    trust_problems: list[str] = []

    for month in month_candidates(date.today()):
        url = f"https://download.db-ip.com/free/{prefix}-{month}.mmdb.gz"
        print(f"trying {url}")
        try:
            compressed = fetch(url, contexts)
        except urllib.error.HTTPError as exc:
            errors.append(f"{month}: HTTP {exc.code}")
            continue
        except DownloadError as exc:
            errors.append(f"{month}: {exc}")
            trust_problems.extend(exc.problems)
            if exc.fatal:
                break
            continue

        data = gzip.GzipFile(fileobj=io.BytesIO(compressed)).read()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        print(f"saved {dest} ({len(data) / 1_048_576:.1f} MiB)")
        return dest

    raise DownloadError(f"could not download {prefix}", errors + trust_problems)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", nargs="?", default="geoip", help="directory (or .mmdb path)")
    parser.add_argument("--ca-file", help="explicit CA bundle to use for HTTPS")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification (only if no CA bundle works)",
    )
    parser.add_argument(
        "--no-asn",
        action="store_true",
        help="skip the ASN database (identity grouping falls back to PTR/domains)",
    )
    args = parser.parse_args()

    destination = Path(args.destination)
    target = (
        destination
        if destination.suffix == ".mmdb"
        else destination / "dbip-country-lite.mmdb"
    )
    try:
        download(target, ca_file=args.ca_file, insecure=args.insecure)
        if destination.suffix != ".mmdb" and not args.no_asn:
            asn_target = destination / "dbip-asn-lite.mmdb"
            try:
                download(
                    asn_target,
                    prefix="dbip-asn-lite",
                    ca_file=args.ca_file,
                    insecure=args.insecure,
                )
            except DownloadError as exc:
                print(f"WARNING: ASN database not downloaded: {exc}", file=sys.stderr)
                print("Identity grouping will fall back to domains and PTR.", file=sys.stderr)
    except DownloadError as exc:
        print(exc, file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        if any("CERTIFICATE_VERIFY_FAILED" in problem for problem in exc.problems):
            print(
                "\nHint: your Python has no usable CA bundle. Options:\n"
                "  - run with the project venv: ./.venv/bin/python scripts/fetch_geoip.py\n"
                "  - pass a bundle:            --ca-file /etc/ssl/cert.pem\n"
                "  - install certifi:          python3 -m pip install certifi\n",
                file=sys.stderr,
            )
        return 1
    print("Set GEOIP_DB / GEOIP_ASN_DB if the files are not in data/geoip/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
