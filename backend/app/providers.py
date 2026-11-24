"""Human-friendly names for the organisations that send reports."""

from __future__ import annotations

from dataclasses import dataclass

PROVIDERS: dict[str, tuple[str, str]] = {
    "google.com": ("Google", "#4285f4"),
    "googlemail.com": ("Google", "#4285f4"),
    "microsoft.com": ("Microsoft", "#0f6cbd"),
    "outlook.com": ("Microsoft", "#0f6cbd"),
    "outlook.de": ("Microsoft", "#0f6cbd"),
    "hotmail.com": ("Microsoft", "#0f6cbd"),
    "live.com": ("Microsoft", "#0f6cbd"),
    "protection.outlook.com": ("Microsoft", "#0f6cbd"),
    "yahoo.com": ("Yahoo", "#6001d2"),
    "yahoo-inc.com": ("Yahoo", "#6001d2"),
    "yahoodns.net": ("Yahoo", "#6001d2"),
    "mailgun.org": ("Mailgun", "#f04438"),
    "mailgun.com": ("Mailgun", "#f04438"),
    "mailgun.net": ("Mailgun", "#f04438"),
    "amazonses.com": ("Amazon SES", "#ff9900"),
    "amazon.com": ("Amazon SES", "#ff9900"),
    "sendgrid.net": ("SendGrid", "#1a82e2"),
    "sendgrid.com": ("SendGrid", "#1a82e2"),
    "fastmail.com": ("Fastmail", "#0067b9"),
    "fastmail.fm": ("Fastmail", "#0067b9"),
    "messagingengine.com": ("Fastmail", "#0067b9"),
    "icloud.com": ("Apple", "#4b5563"),
    "apple.com": ("Apple", "#4b5563"),
    "protonmail.ch": ("Proton Mail", "#6d4aff"),
    "proton.me": ("Proton Mail", "#6d4aff"),
    "zoho.com": ("Zoho", "#e42527"),
    "zoho.eu": ("Zoho", "#e42527"),
    "comcast.net": ("Comcast", "#e11d48"),
    "gmx.net": ("GMX", "#1c4fd8"),
    "gmx.de": ("GMX", "#1c4fd8"),
    "web.de": ("Web.de", "#e2001a"),
    "1und1.de": ("IONOS", "#003d8f"),
    "ionos.com": ("IONOS", "#003d8f"),
    "t-online.de": ("T-Online", "#e20074"),
    "yandex.ru": ("Yandex", "#fc3f1d"),
    "mail.ru": ("Mail.ru", "#005ff9"),
    "qq.com": ("Tencent", "#12b7f5"),
    "163.com": ("NetEase", "#d7000f"),
    "netease.com": ("NetEase", "#d7000f"),
    "seznam.cz": ("Seznam", "#cc0000"),
    "aol.com": ("AOL", "#000000"),
    "proofpoint.com": ("Proofpoint", "#f47b20"),
    "pphosted.com": ("Proofpoint", "#f47b20"),
    "mimecast.com": ("Mimecast", "#00a0df"),
    "barracuda.com": ("Barracuda", "#00a0df"),
    "barracudanetworks.com": ("Barracuda", "#00a0df"),
    "rackspace.com": ("Rackspace", "#c40022"),
    "hetzner.com": ("Hetzner", "#d50c2d"),
    "ovh.net": ("OVH", "#123f6d"),
    "ovh.com": ("OVH", "#123f6d"),
    "gandi.net": ("Gandi", "#1f2937"),
    "postmarkapp.com": ("Postmark", "#ffd24a"),
    "sparkpostmail.com": ("SparkPost", "#fa6423"),
    "mailjet.com": ("Mailjet", "#0a2b4e"),
    "hostpoint.ch": ("Hostpoint", "#e30613"),
    "infomaniak.com": ("Infomaniak", "#0b5cd5"),
    "bluewin.ch": ("Swisscom", "#0057b8"),
    "swisscom.com": ("Swisscom", "#0057b8"),
    "a1.net": ("A1", "#e30613"),
    "aon.at": ("A1", "#e30613"),
    "chello.at": ("Magenta", "#e20074"),
    "kpnmail.nl": ("KPN", "#00a94f"),
    "ziggo.nl": ("Ziggo", "#f60"),
    "mailbox.org": ("mailbox.org", "#1b5e3f"),
    "posteo.de": ("Posteo", "#1e7a4a"),
    "tutanota.com": ("Tuta", "#840010"),
}


@dataclass(frozen=True)
class Provider:
    name: str
    color: str
    known: bool


def provider_for(org_name: str) -> Provider:
    key = (org_name or "").strip().lower().rstrip(".")
    if key in PROVIDERS:
        name, color = PROVIDERS[key]
        return Provider(name=name, color=color, known=True)
    # Fall back to a registrable-domain guess: "mail.example.co.uk" -> "example"
    parts = [part for part in key.split(".") if part]
    label = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "Unknown")
    if label in {"co", "com", "org", "net"} and len(parts) >= 3:
        label = parts[-3]
    display = label.replace("-", " ").title() if label else "Unknown"
    return Provider(name=display, color="#64748b", known=False)
