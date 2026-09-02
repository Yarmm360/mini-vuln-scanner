"""
cve_db.py

A small, CURATED, OFFLINE database of well-known public CVEs for common services
that show up in lab environments (Metasploitable, DVWA, old Apache/nginx/OpenSSH
installs, etc). This is NOT a live feed of the full NVD/MITRE database -- it's a
hand-picked subset intended for teaching/demo purposes.

Each entry maps a product (by common nmap service-detection name) + a version rule
to one or more public CVE IDs, a severity rating, and a short human-readable summary.

To extend this for real-world use, you would replace/augment this with a locally
cached copy of the NVD JSON feeds (https://nvd.nist.gov/vuln/data-feeds), indexed
by CPE, and refreshed periodically.
"""

import re


def _parse_version(v: str):
    """Turn '2.4.49' -> (2, 4, 49). Non-numeric parts are dropped."""
    if not v:
        return ()
    parts = re.split(r"[.\-_]", v)
    nums = []
    for p in parts:
        m = re.match(r"\d+", p)
        if m:
            nums.append(int(m.group()))
        else:
            break
    return tuple(nums)


def _in_range(version_tuple, min_v=None, max_v=None):
    if min_v and version_tuple < _parse_version(min_v):
        return False
    if max_v and version_tuple > _parse_version(max_v):
        return False
    return True


# ---------------------------------------------------------------------------
# Curated CVE entries
# ---------------------------------------------------------------------------
# "products": list of substrings that may appear in nmap's "product" field
# "exact": list of exact version strings this applies to (optional)
# "min"/"max": inclusive version range this applies to (optional)
# If neither "exact" nor "min"/"max" is given, it matches any version of the product.
CVE_DATABASE = [
    {
        "products": ["Apache httpd", "Apache"],
        "min": "2.4.49", "max": "2.4.50",
        "cve_id": "CVE-2021-41773",
        "severity": "Critical",
        "summary": "Path traversal / RCE in Apache HTTP Server 2.4.49-2.4.50 via mod_cgi.",
    },
    {
        "products": ["Apache httpd", "Apache"],
        "min": "2.4.51", "max": "2.4.52",
        "cve_id": "CVE-2022-22720",
        "severity": "High",
        "summary": "HTTP request smuggling due to improper handling of certain requests.",
    },
    {
        "products": ["OpenSSH"],
        "max": "7.2",
        "cve_id": "CVE-2016-0777",
        "severity": "Medium",
        "summary": "OpenSSH client roaming feature can leak private keys to a malicious server.",
    },
    {
        "products": ["OpenSSH"],
        "max": "6.6",
        "cve_id": "CVE-2014-1692",
        "severity": "High",
        "summary": "Buffer overflow in OpenSSH's ssh-keysign that could lead to memory corruption.",
    },
    {
        "products": ["vsftpd"],
        "exact": ["2.3.4"],
        "cve_id": "CVE-2011-2523",
        "severity": "Critical",
        "summary": "Known backdoor in vsftpd 2.3.4 download archive; gives an attacker shell access.",
    },
    {
        "products": ["ProFTPD"],
        "exact": ["1.3.3c"],
        "cve_id": "CVE-2010-4221",
        "severity": "Critical",
        "summary": "Backdoored ProFTPD 1.3.3c source archive allowing remote command execution.",
    },
    {
        "products": ["Samba", "smbd"],
        "min": "3.5.0", "max": "4.4.14",
        "cve_id": "CVE-2017-7494",
        "severity": "Critical",
        "summary": "\"SambaCry\" - remote code execution by uploading a shared library to a writable share.",
    },
    {
        "products": ["Samba", "smbd"],
        "exact": ["3.0.20"],
        "cve_id": "CVE-2007-2447",
        "severity": "Critical",
        "summary": "Username map script command injection allowing remote root shell.",
    },
    {
        "products": ["nginx"],
        "max": "1.20.0",
        "cve_id": "CVE-2021-23017",
        "severity": "High",
        "summary": "Off-by-one heap write in nginx's DNS resolver, could allow memory corruption.",
    },
    {
        "products": ["MySQL"],
        "max": "5.5.99",
        "cve_id": "CVE-2012-2122",
        "severity": "High",
        "summary": "Authentication bypass allowing repeated login attempts to eventually succeed regardless of password.",
    },
    {
        "products": ["Unrealircd", "UnrealIRCd"],
        "exact": ["3.2.8.1"],
        "cve_id": "CVE-2010-2075",
        "severity": "Critical",
        "summary": "Backdoored UnrealIRCd download allowing arbitrary command execution.",
    },
    {
        "products": ["distccd", "distcc"],
        "cve_id": "CVE-2004-2687",
        "severity": "Critical",
        "summary": "distcc daemon can be abused to execute arbitrary commands if exposed without access controls.",
    },
    {
        "products": ["ISC BIND", "named"],
        "max": "9.11.36",
        "cve_id": "CVE-2020-8616",
        "severity": "Medium",
        "summary": "BIND resolver flaw allowing amplification / cache-poisoning style abuse.",
    },
    {
        "products": ["Microsoft ftpd", "Microsoft IIS httpd"],
        "cve_id": "CVE-2010-3972",
        "severity": "High",
        "summary": "IIS FTP service stack buffer overflow in certain versions leading to denial of service or RCE.",
    },
    {
        "products": ["PHP"],
        "max": "5.6.99",
        "cve_id": "CVE-2019-11043",
        "severity": "Critical",
        "summary": "PHP-FPM underflow leading to RCE when chained with certain nginx misconfigurations.",
    },
]


def find_cves(product: str, version: str):
    """
    Look up known CVEs for a given nmap-reported product + version string.
    Returns a list of dicts: [{cve_id, severity, summary}, ...]
    """
    if not product:
        return []

    version_tuple = _parse_version(version) if version else ()
    matches = []

    for entry in CVE_DATABASE:
        if not any(p.lower() in product.lower() for p in entry["products"]):
            continue

        if "exact" in entry:
            if version and version in entry["exact"]:
                matches.append(entry)
            continue

        if "min" in entry or "max" in entry:
            if version_tuple and _in_range(version_tuple, entry.get("min"), entry.get("max")):
                matches.append(entry)
            continue

        # No version constraint at all -- matches any version of this product
        matches.append(entry)

    return [
        {"cve_id": m["cve_id"], "severity": m["severity"], "summary": m["summary"]}
        for m in matches
    ]
